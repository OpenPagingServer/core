import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pymysql
from dotenv import load_dotenv
from waitress.server import create_server

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")
CHARSET = "utf8mb4"
WEB_ERROR_DIR = BASE_DIR / "srv" / "web" / "errors"
MULTICAST_GATEWAY_PROVISION_PATH = "/.well-known/openpagingserver/multicast-gateway-provision"
MULTICAST_GATEWAY_FAILED_WINDOW_SECONDS = 24 * 60 * 60
MULTICAST_GATEWAY_BAN_SECONDS = 48 * 60 * 60
MULTICAST_GATEWAY_FAILED_LIMIT = 5
MAX_SPECIAL_JSON_BODY = 65536
DEMO_MODAL_ENVIRON_KEY = "ops.demo_modal"


def connect(cursorclass=pymysql.cursors.DictCursor):
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        charset=CHARSET,
        cursorclass=cursorclass,
        autocommit=False,
    )


pdo = connect


def db():
    return connect()


class MulticastGatewayProvisionBanStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.failures = {}
        self.banned_until = {}

    def _prune_failures_locked(self, now_value):
        cutoff = now_value - MULTICAST_GATEWAY_FAILED_WINDOW_SECONDS
        expired = []
        for ip, attempts in self.failures.items():
            kept = [attempt for attempt in attempts if attempt >= cutoff]
            if kept:
                self.failures[ip] = kept
            else:
                expired.append(ip)
        for ip in expired:
            self.failures.pop(ip, None)

    def is_banned(self, ip):
        now_value = time.time()
        with self.lock:
            until = self.banned_until.get(str(ip or ""))
            if until is None:
                return False
            if until > now_value:
                return True
            self.banned_until.pop(str(ip or ""), None)
            return False

    def note_success(self, ip):
        with self.lock:
            self.failures.pop(str(ip or ""), None)

    def note_failure(self, ip):
        now_value = time.time()
        banned = False
        banned_until = None
        with self.lock:
            self._prune_failures_locked(now_value)
            key = str(ip or "")
            attempts = list(self.failures.get(key) or [])
            attempts.append(now_value)
            self.failures[key] = attempts
            if len(attempts) >= MULTICAST_GATEWAY_FAILED_LIMIT:
                banned = True
                banned_until = now_value + MULTICAST_GATEWAY_BAN_SECONDS
                self.banned_until[key] = banned_until
                self.failures.pop(key, None)
        return banned, banned_until


multicast_gateway_ban_store = MulticastGatewayProvisionBanStore()


def read_web_settings():
    defaults = {
        "webserver_enable": "1",
        "webserver_http_port": "80",
        "webserver_https_enable": "0",
        "webserver_https_port": "443",
        "webserver_https_privkey": "",
        "webserver_https_cert": "",
        "webserver_http_to_https": "0",
        "webserver_hsts": "0",
        "api_http_enable": "0",
        "api_http_port": "8088",
        "api_https_enable": "0",
        "api_https_port": "8089",
        "api_https_cert": "",
        "api_https_privkey": "",
        "api_http_to_https": "0",
        "api_hsts": "0",
    }
    if not all([DB_HOST, DB_USER, DB_NAME]):
        return defaults
    try:
        conn = db()
    except Exception as exc:
        print(f"webd database connection failed, using defaults: {exc}", flush=True)
        return defaults
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT parameter, value FROM systemsettings WHERE parameter IN "
                "('webserver_enable','webserver_http_port','webserver_https_enable','webserver_https_port',"
                "'webserver_https_privkey','webserver_https_cert','webserver_http_to_https','webserver_hsts',"
                "'api_http_enable','api_http_port','api_https_enable','api_https_port','api_https_cert',"
                "'api_https_privkey','api_http_to_https','api_hsts')"
            )
            for row in cur.fetchall():
                defaults[str(row["parameter"])] = str(row["value"])
    finally:
        conn.close()
    return defaults


def enabled(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def port_value(value, default=80):
    try:
        port = int(str(value or "").strip())
    except ValueError:
        return int(default)
    if not 1 <= port <= 65535:
        return int(default)
    return port


def ports_to_try(configured_port, fallback_port):
    configured = port_value(configured_port, fallback_port)
    ports = [configured]
    if configured != fallback_port:
        ports.append(fallback_port)
    return ports


def parse_proxy_allowlist(raw_value):
    tokens = []
    for part in str(raw_value or "").split(","):
        token = part.strip().strip("'").strip('"')
        if token:
            tokens.append(token)
    allowlist = []
    for token in tokens:
        try:
            if "/" in token:
                allowlist.append(ipaddress.ip_network(token, strict=False))
            else:
                allowlist.append(ipaddress.ip_address(token))
        except ValueError:
            print(f"webd ignoring invalid reverse proxy allowlist entry: {token}", flush=True)
    return tuple(allowlist)


def proxy_is_trusted(remote_addr, allowlist):
    try:
        remote_ip = ipaddress.ip_address(str(remote_addr or "").strip())
    except ValueError:
        return False
    for entry in allowlist:
        if isinstance(entry, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if remote_ip == entry:
                return True
        elif remote_ip in entry:
            return True
    return False


def forwarded_for_client_ip(value):
    for part in str(value or "").split(","):
        token = part.strip()
        if not token:
            continue
        try:
            return str(ipaddress.ip_address(token))
        except ValueError:
            continue
    return ""


def request_client_ip(remote_addr, headers, allowlist):
    if using_reverse_proxy_headers(headers) and proxy_is_trusted(remote_addr, allowlist):
        for name in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip", "true-client-ip"):
            forwarded = forwarded_for_client_ip((headers or {}).get(name))
            if forwarded:
                return forwarded
    return str(remote_addr or "").strip()


class ReverseProxyTrustMiddleware:
    def __init__(self, app, allowlist, denied_html, default_scheme="http"):
        self.app = app
        self.allowlist = allowlist
        self.denied_html = denied_html
        self.default_scheme = str(default_scheme or "http").lower()

    def __call__(self, environ, start_response):
        if self.default_scheme in {"http", "https"}:
            environ["wsgi.url_scheme"] = self.default_scheme
            environ["HTTPS"] = "on" if self.default_scheme == "https" else "off"
        ops_forwarded_proto = str(environ.get("HTTP_X_OPS_FORWARDED_PROTO") or "").split(",", 1)[0].strip().lower()
        ops_forwarded_port = str(environ.get("HTTP_X_OPS_FORWARDED_PORT") or "").split(",", 1)[0].strip()
        if ops_forwarded_proto in {"http", "https"}:
            environ["wsgi.url_scheme"] = ops_forwarded_proto
            environ["HTTPS"] = "on" if ops_forwarded_proto == "https" else "off"
        if ops_forwarded_port.isdigit():
            environ["SERVER_PORT"] = ops_forwarded_port
        using_reverse_proxy = any(
            environ.get(name)
            for name in (
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED_PROTO",
                "HTTP_X_FORWARDED_HOST",
                "HTTP_X_FORWARDED_PORT",
                "HTTP_X_FORWARDED_SERVER",
                "HTTP_X_REAL_IP",
                "HTTP_X_PROXYUSER_IP",
                "HTTP_TRUE_CLIENT_IP",
                "HTTP_CF_CONNECTING_IP",
                "HTTP_CF_RAY",
            )
        )
        remote_addr = environ.get("HTTP_X_OPS_REMOTE_ADDR") or environ.get("REMOTE_ADDR", "")
        client_addr = forwarded_for_client_ip(environ.get("HTTP_X_OPS_CLIENT_ADDR"))
        if remote_addr:
            environ["REMOTE_ADDR"] = remote_addr
        if using_reverse_proxy:
            if not proxy_is_trusted(remote_addr, self.allowlist):
                body = self.denied_html
                start_response(
                    "403 Forbidden",
                    [
                        ("Content-Type", "text/html; charset=utf-8"),
                        ("Content-Length", str(len(body))),
                    ],
                )
                return [body]
            forwarded_proto = str(environ.get("HTTP_X_FORWARDED_PROTO") or "").split(",", 1)[0].strip()
            forwarded_host = str(environ.get("HTTP_X_FORWARDED_HOST") or "").split(",", 1)[0].strip()
            forwarded_port = str(environ.get("HTTP_X_FORWARDED_PORT") or "").split(",", 1)[0].strip()
            if forwarded_proto:
                environ["wsgi.url_scheme"] = forwarded_proto
                environ["HTTPS"] = "on" if forwarded_proto == "https" else "off"
            if forwarded_host:
                environ["HTTP_HOST"] = forwarded_host
                if ":" in forwarded_host:
                    host_name, host_port = forwarded_host.rsplit(":", 1)
                    environ["SERVER_NAME"] = host_name
                    if host_port.isdigit():
                        environ["SERVER_PORT"] = host_port
                else:
                    environ["SERVER_NAME"] = forwarded_host
            elif forwarded_port and forwarded_port.isdigit():
                environ["SERVER_PORT"] = forwarded_port
            forwarded_for = forwarded_for_client_ip(environ.get("HTTP_X_FORWARDED_FOR"))
            if forwarded_for:
                environ["REMOTE_ADDR"] = forwarded_for
        if client_addr:
            environ["REMOTE_ADDR"] = client_addr
        return self.app(environ, start_response)


class HSTSMiddleware:
    def __init__(self, app, enabled=False):
        self.app = app
        self.enabled = bool(enabled)

    def __call__(self, environ, start_response):
        def with_hsts(status, headers, exc_info=None):
            if self.enabled and str(environ.get("wsgi.url_scheme") or "").lower() == "https":
                headers = [(name, value) for name, value in headers if name.lower() != "strict-transport-security"]
                headers.append(("Strict-Transport-Security", "max-age=31536000"))
            return start_response(status, headers, exc_info)

        return self.app(environ, with_hsts)


class StripServerHeaderMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def filtered_start_response(status, headers, exc_info=None):
            filtered = [(name, value) for name, value in headers if name.lower() != "server"]
            return start_response(status, filtered, exc_info)

        return self.app(environ, filtered_start_response)


class DemoModeQueryMiddleware:
    """Expose the demo-modal query trigger to the web application in demo mode."""

    def __init__(self, app, demo_mode=False):
        self.app = app
        self.demo_mode = enabled(demo_mode)

    def __call__(self, environ, start_response):
        if self.demo_mode:
            query = str(environ.get("QUERY_STRING") or "")
            if any(name.lower() == "demomodal" for name, _value in parse_qsl(query, keep_blank_values=True)):
                environ[DEMO_MODAL_ENVIRON_KEY] = "1"
        return self.app(environ, start_response)


def load_reverse_proxy_denied_html():
    path = WEB_ERROR_DIR / "503-RP.html"
    if path.is_file():
        return path.read_bytes()
    return b"<html><body><h1>403 Forbidden</h1><p>This request came through an untrusted reverse proxy.</p></body></html>"


def create_waitress_server(app, port, trusted_proxy_allowlist=(), denied_html=None, hsts_enabled=False, default_scheme="http"):
    denied_html = denied_html if denied_html is not None else load_reverse_proxy_denied_html()
    wrapped = HSTSMiddleware(app, hsts_enabled)
    wrapped = ReverseProxyTrustMiddleware(wrapped, trusted_proxy_allowlist, denied_html, default_scheme)
    wrapped = StripServerHeaderMiddleware(wrapped)
    return create_server(wrapped, host="127.0.0.1", port=port, ident="")


def recv_until(sock, marker, limit=65536):
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def split_head_body(data):
    head, sep, body = bytes(data or b"").partition(b"\r\n\r\n")
    if not sep:
        return bytes(data or b""), b""
    return head + sep, body


def parse_request_head(head_bytes):
    text = head_bytes.decode("iso-8859-1", errors="ignore")
    head, _, _ = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    request_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    parts = request_line.split()
    target = parts[1] if len(parts) >= 2 else "/"
    parsed = urlsplit(target)
    return request_line, parsed.path or "/", headers


def request_method(request_line):
    parts = str(request_line or "").split()
    return parts[0].upper() if parts else "GET"


def content_length_value(headers):
    raw = str((headers or {}).get("content-length") or "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return -1
    return value if value >= 0 else -1


def recv_request_body(sock, initial_body, content_length, limit=MAX_SPECIAL_JSON_BODY):
    if content_length < 0 or content_length > limit:
        raise ValueError("Request body is too large.")
    data = bytearray(initial_body or b"")
    while len(data) < content_length:
        chunk = sock.recv(min(65536, content_length - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data[:content_length])


def status_text(status_code):
    return {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        405: "Method Not Allowed",
        413: "Payload Too Large",
        500: "Internal Server Error",
    }.get(int(status_code), "OK")


def send_json_response(client, status_code, payload, head_only=False):
    body = json.dumps(payload).encode("utf-8")
    header = (
        f"HTTP/1.1 {int(status_code)} {status_text(status_code)}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("iso-8859-1")
    client.sendall(header if head_only else (header + body))


def normalized_request_host(headers):
    raw = str((headers or {}).get("x-forwarded-host") or (headers or {}).get("host") or "").split(",", 1)[0].strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlsplit(raw)
        return str(parsed.hostname or "").strip()
    if raw.startswith("[") and "]" in raw:
        return raw[1:].split("]", 1)[0].strip()
    if raw.count(":") == 1:
        return raw.split(":", 1)[0].strip()
    return raw


def parsed_request_target(request_line):
    parts = str(request_line or "").split()
    target = parts[1] if len(parts) >= 2 else "/"
    parsed = urlsplit(target)
    path = parsed.path or "/"
    if parsed.query:
        return path + "?" + parsed.query
    return path


def https_redirect_authority(headers, https_port):
    raw = str((headers or {}).get("host") or "").split(",", 1)[0].strip()
    if not raw:
        host = "localhost"
    elif raw.startswith("[") and "]" in raw:
        host = raw.split("]", 1)[0] + "]"
    elif raw.count(":") == 1:
        host = raw.split(":", 1)[0].strip()
    else:
        host = raw
    if int(https_port) == 443:
        return host
    return f"{host}:{int(https_port)}"


def send_redirect_response(client, location, head_only=False):
    body = b"<html><body><h1>308 Permanent Redirect</h1><p>Continue to HTTPS.</p></body></html>"
    header = (
        "HTTP/1.1 308 Permanent Redirect\r\n"
        f"Location: {location}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("iso-8859-1")
    client.sendall(header if head_only else (header + body))


def should_bypass_https_redirect(path, headers):
    if path == MULTICAST_GATEWAY_PROVISION_PATH:
        return True
    upgrade = str((headers or {}).get("upgrade") or "").lower()
    return "websocket" in upgrade


def create_ssl_context(cert_path, key_path):
    certfile = str(cert_path or "").strip()
    keyfile = str(key_path or "").strip()
    if not certfile or not keyfile:
        raise ValueError("HTTPS certificate and private key paths are required when HTTPS is enabled.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def query_one(sql, params=None):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()
    finally:
        conn.close()


def execute(sql, params=None):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
        conn.commit()
    finally:
        conn.close()


def load_multicast_gateway_provision_handler():
    from multicastgatewayd import provision_gateway_peer

    return provision_gateway_peer


def using_reverse_proxy_headers(headers):
    return any(
        headers.get(name)
        for name in (
            "forwarded",
            "via",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-real-ip",
            "x-proxyuser-ip",
            "true-client-ip",
            "cf-connecting-ip",
            "cf-ray",
        )
    )


def rewrite_request_head(head_bytes, extra_headers):
    text = head_bytes.decode("iso-8859-1", errors="ignore")
    head, sep, tail = text.partition("\r\n\r\n")
    if not sep:
        return head_bytes
    lines = head.split("\r\n")
    extra_names = {name.lower() for name in extra_headers}
    lines = [
        line
        for index, line in enumerate(lines)
        if index == 0 or ":" not in line or line.split(":", 1)[0].strip().lower() not in extra_names
    ]
    for name, value in extra_headers.items():
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n" + tail).encode("iso-8859-1", errors="ignore")


def relay_stream(source, target):
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            target.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def reject_forbidden(client, denied_html):
    body = denied_html
    client.sendall(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


class FrontServer:
    def __init__(self, app, port, scheme="http", ssl_context=None, redirect_https_port=None, hsts_enabled=False):
        self.allowlist = parse_proxy_allowlist(os.getenv("WEB_REVERSE_PROXY_ALLOWED"))
        self.denied_html = load_reverse_proxy_denied_html()
        self.scheme = str(scheme or "http").lower()
        self.internal_server = create_waitress_server(app, 0, self.allowlist, self.denied_html, hsts_enabled=hsts_enabled, default_scheme=self.scheme)
        self.internal_port = self.internal_server.effective_port
        self.bind_host = os.getenv("WEB_HOST", "0.0.0.0")
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.bind_host, port))
        self.listener.listen(100)
        self.effective_port = self.listener.getsockname()[1]
        self.ssl_context = ssl_context
        self.redirect_https_port = int(redirect_https_port) if redirect_https_port else None
        self._closed = threading.Event()
        self._internal_thread = None

    def close(self):
        self._closed.set()
        try:
            self.listener.close()
        except OSError:
            pass
        try:
            self.internal_server.close()
        except OSError:
            pass

    def run(self):
        self._internal_thread = threading.Thread(target=self.internal_server.run, daemon=True)
        self._internal_thread.start()
        while not self._closed.is_set():
            try:
                client, addr = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()

    def handle_client(self, client, addr):
        upstream = None
        wrapped_client = client
        try:
            if self.ssl_context is not None:
                wrapped_client = self.ssl_context.wrap_socket(client, server_side=True)
            remote_addr = addr[0]
            if multicast_gateway_ban_store.is_banned(remote_addr):
                wrapped_client.close()
                return
            head = recv_until(wrapped_client, b"\r\n\r\n")
            if not head:
                wrapped_client.close()
                return
            request_line, path, headers = parse_request_head(head)
            if using_reverse_proxy_headers(headers) and not proxy_is_trusted(remote_addr, self.allowlist):
                reject_forbidden(wrapped_client, self.denied_html)
                wrapped_client.close()
                return
            client_ip = request_client_ip(remote_addr, headers, self.allowlist)
            if client_ip != remote_addr and multicast_gateway_ban_store.is_banned(client_ip):
                wrapped_client.close()
                return
            if self.redirect_https_port and not should_bypass_https_redirect(path, headers):
                location = "https://" + https_redirect_authority(headers, self.redirect_https_port) + parsed_request_target(request_line)
                send_redirect_response(wrapped_client, location, head_only=(request_method(request_line) == "HEAD"))
                return
            if path == MULTICAST_GATEWAY_PROVISION_PATH:
                self.handle_multicast_gateway_provision(wrapped_client, client_ip, request_line, headers, head)
                return
            if path == "/live" and "websocket" in str(headers.get("upgrade") or "").lower():
                from livepaged import handle_websocket_client

                handle_websocket_client(wrapped_client, addr, head)
                return
            if path == "/desktop/ws" and "websocket" in str(headers.get("upgrade") or "").lower():
                from clientd import handle_desktop_websocket_client

                handle_desktop_websocket_client(wrapped_client, addr, head)
                return
            upstream = socket.create_connection(("127.0.0.1", self.internal_port), timeout=10)
            upstream.sendall(
                rewrite_request_head(
                    head,
                    {
                        "X-Ops-Remote-Addr": remote_addr,
                        "X-Ops-Client-Addr": client_ip,
                        "X-Ops-Forwarded-Proto": self.scheme,
                        "X-Ops-Forwarded-Port": str(self.effective_port),
                    },
                )
            )
            t1 = threading.Thread(target=relay_stream, args=(wrapped_client, upstream), daemon=True)
            t2 = threading.Thread(target=relay_stream, args=(upstream, wrapped_client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                wrapped_client.close()
            except OSError:
                pass
            if wrapped_client is not client:
                try:
                    client.close()
                except OSError:
                    pass
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    def handle_multicast_gateway_provision(self, client, client_ip, request_line, headers, head):
        method = request_method(request_line)
        if method in {"GET", "HEAD"}:
            send_json_response(
                client,
                200,
                {
                    "status": "success",
                    "service": "multicast-gateway-provision",
                    "path": MULTICAST_GATEWAY_PROVISION_PATH,
                },
                head_only=(method == "HEAD"),
            )
            return
        if method != "POST":
            send_json_response(client, 405, {"status": "error", "message": "Method not allowed."})
            return
        content_length = content_length_value(headers)
        if content_length < 0:
            send_json_response(client, 400, {"status": "error", "message": "Invalid content length."})
            return
        if content_length > MAX_SPECIAL_JSON_BODY:
            send_json_response(client, 413, {"status": "error", "message": "Request body is too large."})
            return
        _head_only, initial_body = split_head_body(head)
        try:
            body = recv_request_body(client, initial_body, content_length)
            payload = json.loads(body.decode("utf-8") or "{}") if content_length else {}
            if not isinstance(payload, dict):
                raise ValueError("JSON payload must be an object.")
        except Exception as exc:
            send_json_response(client, 400, {"status": "error", "message": str(exc)})
            return
        try:
            provision_gateway_peer = load_multicast_gateway_provision_handler()
            status_code, response_payload = provision_gateway_peer(
                query_one,
                execute,
                payload,
                client_ip,
                normalized_request_host(headers),
            )
        except Exception as exc:
            send_json_response(client, 500, {"status": "error", "message": str(exc)})
            return
        if int(status_code) == 401:
            banned, _banned_until = multicast_gateway_ban_store.note_failure(client_ip)
            if banned:
                print(f"webd banned {client_ip} after repeated multicast gateway provisioning failures", flush=True)
        elif int(status_code) < 400:
            multicast_gateway_ban_store.note_success(client_ip)
        send_json_response(client, status_code, response_payload)


def create_front_server(app, port, scheme="http", ssl_context=None, redirect_https_port=None, hsts_enabled=False):
    return FrontServer(
        app,
        port,
        scheme=scheme,
        ssl_context=ssl_context,
        redirect_https_port=redirect_https_port,
        hsts_enabled=hsts_enabled,
    )


def server_ports(label, configured_port):
    if label == "web":
        return ports_to_try(configured_port, 80)
    if label == "web-https":
        return ports_to_try(configured_port, 443)
    return [port_value(configured_port)]


def build_servers(settings):
    servers = []
    if enabled(settings.get("webserver_enable")):
        from srv.web.app import app as web_app

        web_app = DemoModeQueryMiddleware(web_app, enabled(os.getenv("DEMO_MODE")))
        https_enabled = enabled(settings.get("webserver_https_enable"))
        https_port = port_value(settings.get("webserver_https_port"), 443)
        http_redirect = enabled(settings.get("webserver_http_to_https")) and https_enabled
        hsts_enabled = enabled(settings.get("webserver_hsts")) and https_enabled
        servers.append(
            (
                "web",
                "Open Paging Server",
                web_app,
                server_ports("web", settings.get("webserver_http_port")),
                {
                    "scheme": "http",
                    "redirect_https_port": https_port if http_redirect else None,
                    "hsts_enabled": False,
                },
            )
        )
        if https_enabled:
            ssl_context = create_ssl_context(settings.get("webserver_https_cert"), settings.get("webserver_https_privkey"))
            servers.append(
                (
                    "web-https",
                    "Open Paging Server",
                    web_app,
                    server_ports("web-https", settings.get("webserver_https_port")),
                    {
                        "scheme": "https",
                        "ssl_context": ssl_context,
                        "hsts_enabled": hsts_enabled,
                    },
                )
            )
    api_http_enabled = enabled(settings.get("api_http_enable"))
    api_https_enabled = enabled(settings.get("api_https_enable"))
    if api_http_enabled or api_https_enabled:
        from srv.api.app import app as api_app

        api_https_port = port_value(settings.get("api_https_port"), 8089)
        if api_http_enabled:
            servers.append(
                (
                    "api",
                    "Open Paging Server API",
                    api_app,
                    server_ports("api", settings.get("api_http_port")),
                    {
                        "scheme": "http",
                        "redirect_https_port": api_https_port if api_https_enabled and enabled(settings.get("api_http_to_https")) else None,
                        "hsts_enabled": False,
                    },
                )
            )
        if api_https_enabled:
            api_ssl_context = create_ssl_context(settings.get("api_https_cert"), settings.get("api_https_privkey"))
            servers.append(
                (
                    "api-https",
                    "Open Paging Server API",
                    api_app,
                    server_ports("api-https", settings.get("api_https_port")),
                    {
                        "scheme": "https",
                        "ssl_context": api_ssl_context,
                        "hsts_enabled": enabled(settings.get("api_hsts")),
                    },
                )
            )
    return servers


def main():
    settings = read_web_settings()
    specs = build_servers(settings)
    if not specs:
        print("webd disabled because both web and API listeners are off", flush=True)
        return 0

    last_errors = {}
    while True:
        running = []
        failed = False
        try:
            for label, title, app, ports, options in specs:
                server = None
                for port in ports:
                    try:
                        server = create_front_server(app, port, **options)
                        print(f"webd serving {title} on {options.get('scheme', 'http')}://{server.bind_host}:{server.effective_port}", flush=True)
                        break
                    except (OSError, socket.error, ssl.SSLError, ValueError) as exc:
                        last_errors[label] = exc
                        print(f"webd {label} port {port} unavailable: {exc}", flush=True)
                if server is None:
                    failed = True
                    break
                thread = threading.Thread(target=server.run, daemon=True)
                thread.start()
                running.append((server, thread))
            if not failed:
                for _server, thread in running:
                    thread.join()
                return 0
        finally:
            for server, _thread in running:
                server.close()
        wait_bits = []
        for label, _title, _app, ports, _options in specs:
            last_error = last_errors.get(label)
            wait_bits.append(f"{label} ports {', '.join(map(str, ports))}: {last_error}")
        print("webd waiting for ports to become available; " + "; ".join(wait_bits), flush=True)
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
