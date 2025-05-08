# uwebsockets.client (modified for extra_headers and proxy support)

import usocket as socket
import ubinascii as binascii
import urandom as random
import ssl  # Changed from ussl

# Assuming .protocol is in the same directory or accessible in sys.path
from .protocol import Websocket, urlparse # Ensure urlparse handles ws/wss schemes

# Logging has been removed. Use print() for debugging if needed.

class WebsocketClient(Websocket):
    is_client = True

def connect(uri, extra_headers=None, proxy_host=None, proxy_port=None):
    """
    Connect a websocket.
    uri: The WebSocket URI string (e.g., "ws://echo.websocket.org").
    extra_headers: Optional dict or list of tuples for custom WebSocket handshake headers.
    proxy_host: Optional FQDN or IP address of the proxy server.
    proxy_port: Optional port number of the proxy server.
    """

    parsed_uri = urlparse(uri)
    if not parsed_uri:
        raise ValueError("Invalid URI: {}".format(uri))

    # Target server details (always from the original URI)
    target_hostname = parsed_uri.hostname
    target_port = parsed_uri.port
    target_path = parsed_uri.path or b'/' # Ensure path is bytes or default to / if empty
    target_protocol = parsed_uri.protocol # "ws" or "wss"

    # Convert target details to bytes/strings as needed later
    target_hostname_bytes = target_hostname.encode('utf-8') if isinstance(target_hostname, str) else target_hostname
    target_path_bytes = target_path.encode('utf-8') if isinstance(target_path, str) else target_path
    # For ssl.wrap_socket, server_hostname must be a string
    target_server_hostname_str = target_hostname.decode('utf-8') if isinstance(target_hostname, bytes) else target_hostname


    sock = None
    try:
        sock = socket.socket()

        # Determine connection endpoint: proxy or direct target
        conn_hostname = proxy_host if proxy_host else target_hostname
        conn_port = proxy_port if proxy_host and proxy_port else target_port

        if __debug__:
            if proxy_host:
                print("uwebsockets: Connecting via proxy {}:{} to target {}:{}".format(
                    conn_hostname, conn_port, target_hostname, target_port))
            else:
                print("uwebsockets: Opening direct connection to {}:{}".format(conn_hostname, conn_port))

        addr_info = socket.getaddrinfo(conn_hostname, conn_port, 0, socket.SOCK_STREAM)
        if not addr_info:
            raise OSError("Cannot resolve address for {}:{}".format(conn_hostname, conn_port))
        
        sock.connect(addr_info[0][-1])

        # If WSS and proxying, establish CONNECT tunnel first
        if target_protocol == 'wss' and proxy_host and proxy_port:
            if __debug__:
                print("uwebsockets: Establishing CONNECT tunnel via proxy for WSS.")
            
            connect_req = b"CONNECT %s:%d HTTP/1.1\r\n" % (target_hostname_bytes, target_port)
            connect_req += b"Host: %s:%d\r\n" % (target_hostname_bytes, target_port)
            # Some proxies might require User-Agent or Proxy-Authorization
            # if proxy_auth_header: connect_req += proxy_auth_header + b"\r\n"
            connect_req += b"\r\n"
            
            if __debug__: print("uwebsockets: Sending CONNECT request:\n{!r}".format(connect_req))
            sock.write(connect_req)
            
            # Read proxy's response to CONNECT
            # Note: MicroPython's socket.readline() might be blocking or have issues with timeouts.
            # Robust implementation might need a loop with sock.recv(1) and timeout handling.
            # For simplicity, using readline() here.
            status_line = sock.readline()
            if not status_line:
                raise OSError("Proxy closed connection before sending CONNECT response.")
            status_line = status_line.rstrip(b'\r\n')
            if __debug__: print("uwebsockets: Proxy CONNECT response status: {}".format(status_line.decode('utf-8', 'ignore')))

            if not (status_line.startswith(b'HTTP/1.1 200') or status_line.startswith(b'HTTP/1.0 200')):
                # Read rest of proxy error response for debugging
                error_response = status_line + b"\r\n"
                while True:
                    header = sock.readline()
                    if not header or header == b'\r\n': break
                    error_response += header
                raise OSError("Proxy CONNECT request failed: {}".format(error_response.decode('utf-8', 'ignore')))
            
            # Consume any remaining headers from proxy's 200 OK response
            while True:
                header_line = sock.readline()
                if not header_line or header_line == b'\r\n': # Empty line or closed
                    break
                if __debug__: print("uwebsockets: Proxy CONNECT response header: {}".format(header_line.rstrip(b'\\r\\n').decode('utf-8', 'ignore')))
            
            if __debug__: print("uwebsockets: CONNECT tunnel established.")
            # Now, wrap the socket with SSL for the tunnel to the target
            sock = ssl.wrap_socket(sock, server_hostname=target_server_hostname_str)
            if __debug__: print("uwebsockets: Socket wrapped with SSL through proxy tunnel.")

        elif target_protocol == 'wss': # WSS direct connection (no proxy)
            if __debug__: print("uwebsockets: Wrapping socket with SSL for direct WSS connection.")
            sock = ssl.wrap_socket(sock, server_hostname=target_server_hostname_str)
        
        # For 'ws' (non-SSL), no specific pre-handshake action if proxied,
        # but the GET request line will be different (see below).

        # --- Send WebSocket Handshake Request ---
        # This request goes to the target server (directly, or through proxy tunnel,
        # or as an absolute URI to proxy for WS)

        def send_header_line(line_bytes):
            if __debug__:
                try:
                    print("uwebsockets: Sending header: {}".format(line_bytes.decode('utf-8')))
                except UnicodeDecodeError:
                    print("uwebsockets: Sending header (binary): {}".format(line_bytes))
            sock.write(line_bytes + b'\r\n')

        key_bytes = bytes(random.getrandbits(8) for _ in range(16))
        sec_websocket_key = binascii.b2a_base64(key_bytes).strip()

        # Determine the GET request line based on proxy presence for 'ws'
        if target_protocol == 'ws' and proxy_host and proxy_port:
            # For 'ws' over proxy, use absolute URI in GET line.
            # The original 'uri' string passed to connect() is the absolute URI.
            request_uri_bytes = uri.encode('utf-8')
        else:
            # For 'wss' (proxied or direct) or 'ws' (direct), use just the path.
            request_uri_bytes = target_path_bytes
        
        send_header_line(b'GET %s HTTP/1.1' % request_uri_bytes)
        
        # Host header ALWAYS refers to the TARGET server
        send_header_line(b'Host: %s:%d' % (target_hostname_bytes, target_port))
        
        send_header_line(b'Connection: Upgrade')
        send_header_line(b'Upgrade: websocket')
        send_header_line(b'Sec-WebSocket-Key: %s' % sec_websocket_key)
        send_header_line(b'Sec-WebSocket-Version: 13')
        
        origin_protocol_bytes = target_protocol.encode('utf-8') # ws or wss
        send_header_line(b'Origin: %s://%s:%d' % (origin_protocol_bytes, target_hostname_bytes, target_port))

        if extra_headers:
            if isinstance(extra_headers, dict):
                for k, v in extra_headers.items():
                    k_bytes = k.encode('utf-8') if isinstance(k, str) else k
                    v_bytes = v.encode('utf-8') if isinstance(v, str) else v
                    send_header_line(b'%s: %s' % (k_bytes, v_bytes))
            elif isinstance(extra_headers, list):
                for k, v in extra_headers:
                    k_bytes = k.encode('utf-8') if isinstance(k, str) else k
                    v_bytes = v.encode('utf-8') if isinstance(v, str) else v
                    send_header_line(b'%s: %s' % (k_bytes, v_bytes))
        
        send_header_line(b'') # End of headers

        # --- Read WebSocket Handshake Response (from target server) ---
        response_line = sock.readline()
        if not response_line:
            raise OSError("Server closed connection before sending WebSocket handshake response.")
        
        response_line = response_line.rstrip(b'\r\n')
        if __debug__:
            print("uwebsockets: Received status line: {}".format(response_line.decode('utf-8', 'ignore')))

        if not (response_line.startswith(b'HTTP/1.1 101 ') or \
                response_line.startswith(b'HTTP/1.0 101 ') or \
                b' 101 ' in response_line): # More lenient check for 101
            raise ConnectionAbortedError("WebSocket handshake failed: Unexpected HTTP status: {}".format(response_line.decode('utf-8', 'ignore')))

        while True:
            header_line_bytes = sock.readline()
            if not header_line_bytes:
                 raise ConnectionAbortedError("WebSocket handshake failed: Connection closed by server while reading headers.")
            header_line_bytes = header_line_bytes.rstrip(b'\r\n')
            if not header_line_bytes: break # Empty line signifies end of headers
            if __debug__:
                print("uwebsockets: Received header: {}".format(header_line_bytes.decode('utf-8', 'ignore')))

        return WebsocketClient(sock)

    except Exception as e:
        if sock:
            sock.close()
        if __debug__:
            # In MicroPython, printing exception directly is often more informative
            import sys
            print("uwebsockets: Error during connect:")
            sys.print_exception(e)
        raise e
