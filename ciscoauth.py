#!/usr/bin/env python3
# For now it always returns AUTHORIZED. At some point, proper authentication will be added
from http.server import HTTPServer, BaseHTTPRequestHandler

class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"AUTHORIZED")
        else:
            self.send_response(404)
            self.end_headers()

HTTPServer(("0.0.0.0", 8082), AuthHandler).serve_forever()
