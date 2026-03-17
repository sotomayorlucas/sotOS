#!/usr/bin/env python3
"""
sotOS HTTPS Proxy — bridges HTTP (guest) to HTTPS (internet).

The guest OS connects via plain HTTP to this proxy. The proxy
fetches the target URL over HTTPS and returns the response.

Usage:
    python scripts/https_proxy.py [--port PORT]

Guest usage:
    busybox wget http://10.0.2.2:PORT/https://dl-cdn.alpinelinux.org/alpine/v3.19/...

The proxy strips the leading "/" and uses the rest as the target URL.
"""

import http.server
import ssl
import urllib.request
import urllib.error
import sys
import argparse

class HTTPSProxyHandler(http.server.BaseHTTPRequestHandler):
    """Handle GET requests by proxying to the target HTTPS URL."""

    def do_GET(self):
        # The path is the target URL: /https://example.com/path
        target_url = self.path.lstrip("/")
        if not target_url.startswith("http"):
            self.send_error(400, f"Bad URL: {target_url}")
            return

        self.log_message(f"Proxying: {target_url}")
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(target_url, headers={
                "User-Agent": "sotOS-HTTPS-Proxy/1.0",
            })
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                # Forward content headers
                for h in ("Content-Type", "Content-Length", "Content-Disposition"):
                    val = resp.headers.get(h)
                    if val:
                        self.send_header(h, val)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self.send_error(502, str(e))

    def log_message(self, format, *args):
        sys.stderr.write(f"[proxy] {format % args}\n")


def main():
    parser = argparse.ArgumentParser(description="sotOS HTTPS Proxy")
    parser.add_argument("--port", "-p", type=int, default=9443,
                        help="Port to listen on (default: 9443)")
    args = parser.parse_args()

    server = http.server.HTTPServer(("0.0.0.0", args.port), HTTPSProxyHandler)
    print(f"HTTPS proxy listening on port {args.port}")
    print(f"Guest usage: busybox wget http://10.0.2.2:{args.port}/https://example.com/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
