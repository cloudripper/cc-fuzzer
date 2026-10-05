"""A scripted Anthropic Messages endpoint for driving real Claude Code offline.

Each POST /v1/messages answers with the next scripted turn, streamed as SSE
the way the API does. A turn is {"tool": name, "input": {...}} (one tool_use
block), {"tools": [...]} (several; "same_id": true gives them all one id, as a
duplicated stream does) or {"text": "..."} (end_turn). Every request body is appended
to <log> so a test can read back what Claude Code sent: the tool_results its
tools (and hooks) produced. No model, no network, no cost.

    python3 mockmodel.py <port> <script.json> <log.jsonl>
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, SCRIPT, LOG = int(sys.argv[1]), json.load(open(sys.argv[2])), sys.argv[3]
lock = threading.Lock()
state = {"i": 0}


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        if "count_tokens" in self.path:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"input_tokens": 100}')
            return
        req = json.loads(body or b"{}")
        # side requests (titles, summaries) are not the main loop: answer briefly
        main = bool(req.get("tools"))
        with lock:
            with open(LOG, "a") as f:
                f.write(json.dumps({"main": main, "req": req}) + "\n")
            if main:
                turn = SCRIPT[state["i"]] if state["i"] < len(SCRIPT) else {"text": "done"}
                state["i"] += 1
            else:
                turn = {"text": "ok"}
        mid = f"msg_mock_{state['i']}"
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        w = self.wfile.write
        w(sse("message_start", {"type": "message_start", "message": {
            "id": mid, "type": "message", "role": "assistant", "model": req.get("model", "mock"),
            "content": [], "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 1}}}))
        blocks = turn.get("tools") or ([{"tool": turn["tool"], "input": turn["input"]}] if "tool" in turn else [])
        if blocks:
            for k, blk in enumerate(blocks):
                w(sse("content_block_start", {"type": "content_block_start", "index": k, "content_block": {
                    "type": "tool_use", "name": blk["tool"], "input": {},
                    # same_id: every block repeats block 0's id, as a duplicated stream does
                    "id": f"toolu_mock_{state['i']}_{0 if turn.get('same_id') else k}"}}))
                w(sse("content_block_delta", {"type": "content_block_delta", "index": k, "delta": {
                    "type": "input_json_delta", "partial_json": json.dumps(blk["input"])}}))
                w(sse("content_block_stop", {"type": "content_block_stop", "index": k}))
            stop = "tool_use"
        else:
            w(sse("content_block_start", {"type": "content_block_start", "index": 0,
                                          "content_block": {"type": "text", "text": ""}}))
            w(sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                          "delta": {"type": "text_delta", "text": turn["text"]}}))
            w(sse("content_block_stop", {"type": "content_block_stop", "index": 0}))
            stop = "end_turn"
        w(sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                "usage": {"output_tokens": 10}}))
        w(sse("message_stop", {"type": "message_stop"}))


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
