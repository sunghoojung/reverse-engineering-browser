from __future__ import annotations


class DebuggerBridgeError(RuntimeError):
    pass


class ProtocolError(DebuggerBridgeError):
    pass


class WebSocketClosed(DebuggerBridgeError):
    pass
