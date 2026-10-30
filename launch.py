"""Lattice Live: local-only, read-only Windows dashboard server.

Requires Python 3.10+, Windows PowerShell 5.1 (Windows collectors).
Does not require package installation, elevated permissions, or network access.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import threading
import urllib.parse
import webbrowser
import time
import os
import signal
import sys
from telemetry import WindowsTelemetry

BASE=Path(__file__).resolve().parent
CONTENT={
    '/':('index.html','text/html; charset=utf-8'),
    '/index.html':('index.html','text/html; charset=utf-8'),
    '/assets/lattice.png':('assets/LATTICE_ID_PORTRAIT.png','image/png'),
}

def make_handler(telemetry):
    class LocalHandler(BaseHTTPRequestHandler):
        def _respond(self,code,body,kind='application/json; charset=utf-8'):
            self.send_response(code)
            self.send_header('Content-Type',kind)
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            # Reject DNS rebinding and any unexpected Host header.
            host=self.headers.get('Host','')
            allowed=(f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}')
            if host not in allowed:
                return self._respond(403,b'{"error":"invalid local host"}')
            route=urllib.parse.urlsplit(self.path).path
            if route=='/api/snapshot':
                payload=json.dumps(telemetry.snapshot(),separators=(',',':'),allow_nan=False).encode('utf-8')
                return self._respond(200,payload)
            if route in CONTENT:
                rel,kind=CONTENT[route]
                try:data=(BASE/rel).read_bytes()
                except OSError:return self._respond(404,b'not found','text/plain')
                return self._respond(200,data,kind)
            return self._respond(404,b'not found','text/plain')
        def do_POST(self):return self._respond(405,b'{"error":"read-only dashboard"}')
        def do_PUT(self):return self._respond(405,b'{"error":"read-only dashboard"}')
        def do_DELETE(self):return self._respond(405,b'{"error":"read-only dashboard"}')
        def log_message(self,fmt,*args):
            # No raw URLs or IP addresses written to disk.
            return
    return LocalHandler

def start_server(telemetry,port=0):
    server=ThreadingHTTPServer(('127.0.0.1',port),make_handler(telemetry))
    server.daemon_threads=True
    return server

def main():
    parser=argparse.ArgumentParser(description='Lattice Windows local security dashboard')
    parser.add_argument('--demo',action='store_true',help='Explicit synthetic presentation preview. NOT LIVE SECURITY DATA.')
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--port',type=int,default=0,help='Bind to 127.0.0.1 at a fixed port (default: random)')
    args=parser.parse_args()
    t=WindowsTelemetry(demo=args.demo)
    t.start()
    try: server=start_server(t,args.port)
    except Exception:
        t.stop();raise
    url=f'http://127.0.0.1:{server.server_port}/'
    print('Lattice Windows Live v0.3.0',flush=True)
    print(('*** SYNTHETIC DEMONSTRATION — NO LIVE READINGS ***' if args.demo else 'Read-only local Windows telemetry'),flush=True)
    print('Dashboard:',url,flush=True)
    print('Press Ctrl+C to stop; no Windows configuration will be changed.',flush=True)
    if not args.no_browser:
        threading.Thread(target=lambda:(time.sleep(.7),webbrowser.open(url)),daemon=True).start()
    try:server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:pass
    finally:
        server.server_close();t.stop()

if __name__=='__main__':main()
