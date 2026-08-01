"""CDP client — attach to a human-driven Chrome and observe, never drive.

Overwatch connects to Chrome's DevTools Protocol endpoint (the same one a
human opens with `--remote-debugging-port=9222`) over a raw WebSocket and
subscribes to Network events. It enables Network tracking and reads response
bodies at `Network.loadingFinished` — the one moment a body is guaranteed to
still be in the DevTools cache. **Bodies evict on navigation**, so a body not
captured at loadingFinished is gone; this is why the observer reacts to the
event rather than polling.

It issues exactly three kinds of CDP command: `Network.enable` (start the
event stream), `Network.getResponseBody` (read a body already in cache), and
target discovery over the HTTP `/json` endpoint. None of these emit a request
to the target application — they are all reads against the browser's own
in-memory state. The observer is indistinguishable from a user because it *is*
the user's traffic.

Dependency note: uses `websocket-client` (import name `websocket`) and stdlib
`urllib`. Kept import-light so the package installs with zero heavy deps and the
detector layer stays usable stand-alone (e.g. `scan-har`) without a browser.
"""
from __future__ import annotations

import json
import urllib.request

from .detectors import Exchange


def discover_targets(host: str = "127.0.0.1", port: int = 9222):
    """List the browser's open page targets via the CDP HTTP endpoint.

    Returns the raw list of target dicts (id, title, url, webSocketDebuggerUrl).
    This is a read against the browser, not the application.
    """
    url = f"http://{host}:{port}/json"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


class CDPObserver:
    """Passive Network observer over a single page target's CDP WebSocket.

    Usage:
        obs = CDPObserver(ws_debugger_url)
        for exchange in obs.watch(seconds=120):
            findings = run_detectors(exchange)
            ...

    The observer only ever sends Network.enable and Network.getResponseBody.
    It never navigates, clicks, or injects — the human owns the wheel.
    """

    def __init__(self, ws_url: str, body_max: int = 512_000):
        try:
            import websocket  # websocket-client
        except ImportError as e:  # pragma: no cover - dependency hint
            raise ImportError(
                "overwatch needs the 'websocket-client' package for live watch "
                "(pip install websocket-client). The offline scan-har path does not."
            ) from e
        self._websocket = websocket
        self.ws_url = ws_url
        self.body_max = body_max
        self._id = 0
        self._ws = None
        # requestId -> partial request metadata seen on Network.requestWillBeSent
        self._pending: dict = {}
        # requestId -> response metadata seen on Network.responseReceived
        self._responses: dict = {}

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, method: str, params: dict | None = None) -> int:
        mid = self._next_id()
        self._ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        return mid

    def _get_body(self, request_id: str) -> str:
        """Ask the browser for a response body already in its cache."""
        mid = self._send("Network.getResponseBody", {"requestId": request_id})
        # read frames until we see our reply id
        while True:
            msg = json.loads(self._ws.recv())
            if msg.get("id") == mid:
                result = msg.get("result") or {}
                body = result.get("body", "")
                if result.get("base64Encoded") and body:
                    import base64
                    try:
                        body = base64.b64decode(body).decode("utf-8", "replace")
                    except Exception:
                        body = ""
                return body[: self.body_max]
            # interleaved events during the round-trip: fold them in
            self._absorb_event(msg)

    def _absorb_event(self, msg: dict):
        method = msg.get("method")
        params = msg.get("params") or {}
        if method == "Network.requestWillBeSent":
            req = params.get("request") or {}
            self._pending[params.get("requestId")] = {
                "url": req.get("url", ""),
                "method": req.get("method", "GET"),
                "headers": req.get("headers") or {},
            }
        elif method == "Network.responseReceived":
            resp = params.get("response") or {}
            self._responses[params.get("requestId")] = {
                "status": resp.get("status", 0),
                "headers": resp.get("headers") or {},
            }

    def watch(self, seconds: int | None = None, max_exchanges: int | None = None):
        """Yield an Exchange for each completed response during the window.

        Runs until `seconds` elapse (wall clock, tracked by the caller's timer)
        or `max_exchanges` are emitted. Because Date.now-style timing lives in
        the caller, this loop is bounded by max_exchanges and by the human
        closing the tab; a plain time budget is enforced by the CLI wrapper.
        """
        ws = self._ws = self._websocket.create_connection(
            self.ws_url, max_size=None, timeout=seconds or 60
        )
        self._send("Network.enable")
        emitted = 0
        try:
            while True:
                try:
                    msg = json.loads(ws.recv())
                except self._websocket.WebSocketTimeoutException:
                    break
                except (self._websocket.WebSocketConnectionClosedException, OSError):
                    break
                method = msg.get("method")
                if method in ("Network.requestWillBeSent", "Network.responseReceived"):
                    self._absorb_event(msg)
                elif method == "Network.loadingFinished":
                    rid = (msg.get("params") or {}).get("requestId")
                    req = self._pending.get(rid, {})
                    resp = self._responses.get(rid, {})
                    body = ""
                    try:
                        body = self._get_body(rid)
                    except Exception:
                        body = ""   # body already evicted or not retrievable
                    yield Exchange(
                        url=req.get("url", ""),
                        method=req.get("method", "GET"),
                        request_headers=req.get("headers", {}),
                        status=resp.get("status", 0),
                        response_headers=resp.get("headers", {}),
                        body=body,
                    )
                    emitted += 1
                    self._pending.pop(rid, None)
                    self._responses.pop(rid, None)
                    if max_exchanges and emitted >= max_exchanges:
                        break
        finally:
            try:
                ws.close()
            except Exception:
                pass


def exchanges_from_har(har: dict):
    """Yield Exchanges from a HAR export (offline path — no browser needed).

    A HAR is what you get from DevTools "Save all as HAR" or a proxy dump. This
    lets Overwatch run the same taxonomy over a capture taken by someone else,
    or over a session recorded earlier, with no live connection.
    """
    for entry in (har.get("log", {}).get("entries", []) or []):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        req_headers = {h["name"]: h["value"] for h in req.get("headers", [])}
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", [])}
        content = resp.get("content", {}) or {}
        body = content.get("text", "") or ""
        yield Exchange(
            url=req.get("url", ""),
            method=req.get("method", "GET"),
            request_headers=req_headers,
            status=resp.get("status", 0),
            response_headers=resp_headers,
            body=body,
        )
