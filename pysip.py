import hashlib
import re
import secrets
import sqlite3
import socketserver

DB_FILE = "sip_users.db"
REALM = "sip.local"

# In-memory routing state
REGISTRY = {}   # {"1001": ("192.168.1.10", 5060)}
CALLS = {}      # {"call-id": {"caller": (...), "callee": (...)}}


def get_user_ha1(username: str):
    """Fetches the HA1 digest hash from SQLite."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ha1 FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def parse_sip_message(raw_data: str):
    parts = raw_data.split("\r\n\r\n", 1)
    lines = parts[0].split("\r\n")
    start_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip().title()] = val.strip()
    body = parts[1] if len(parts) > 1 else ""
    return start_line, headers, body


def parse_auth_header(auth_header: str):
    """Parses Digest key="val" parameters into a dictionary."""
    if not auth_header.startswith("Digest "):
        return {}
    content = auth_header[7:]
    pattern = r'(\w+)=(?:"([^"]*)"|([^,\s]*))'
    return {k: (v1 or v2) for k, v1, v2 in re.findall(pattern, content)}


def verify_digest(method: str, auth_params: dict) -> bool:
    """Verifies MD5 Digest auth response against stored HA1."""
    username = auth_params.get("username")
    ha1 = get_user_ha1(username)
    if not ha1:
        return False

    uri = auth_params.get("uri", "")
    nonce = auth_params.get("nonce", "")
    nc = auth_params.get("nc")
    cnonce = auth_params.get("cnonce")
    qop = auth_params.get("qop")
    client_response = auth_params.get("response", "")

    # Calculate HA2 = MD5(Method:DigestURI)
    ha2 = hashlib.md5(f"{method}:{uri}".encode("utf-8")).hexdigest()

    # Calculate expected response
    if qop and qop.lower() == "auth":
        expected = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode("utf-8")
        ).hexdigest()
    else:
        # Standard non-qop RFC 2069 fallback
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()

    return secrets.compare_digest(expected.lower(), client_response.lower())


def extract_user(uri_or_header: str):
    match = re.search(r"sip:([^@:;>]+)", uri_or_header)
    return match.group(1) if match else None


class SIPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        raw_data = self.request[0].decode("utf-8", errors="ignore")
        sock = self.request[1]
        client_addr = self.client_address

        if not raw_data.strip():
            return

        start_line, headers, body = parse_sip_message(raw_data)
        call_id = headers.get("Call-Id")

        if start_line.startswith("SIP/2.0"):
            self.handle_response(raw_data, start_line, call_id, sock, client_addr)
        else:
            self.handle_request(raw_data, start_line, headers, call_id, sock, client_addr)

    def handle_request(self, raw_data, start_line, headers, call_id, sock, client_addr):
        method = start_line.split()[0].upper()
        print(f"[REQ] {method} from {client_addr}")

        if method == "REGISTER":
            self.process_register(raw_data, method, start_line, headers, sock, client_addr)
        elif method == "INVITE":
            self.process_invite(raw_data, start_line, headers, call_id, sock, client_addr)
        elif method in ("ACK", "BYE", "CANCEL"):
            self.forward_in_dialog(raw_data, method, call_id, sock, client_addr)
        elif method == "OPTIONS":
            resp = (
                f"SIP/2.0 200 OK\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            sock.sendto(resp.encode("utf-8"), client_addr)

    def process_register(self, raw_data, method, start_line, headers, sock, client_addr):
        extension = extract_user(headers.get("To", ""))
        auth_header = headers.get("Authorization")

        # Step 1: If no authorization header present, challenge the client
        if not auth_header:
            self.send_401_challenge(headers, sock, client_addr)
            return

        # Step 2: Validate provided credentials
        auth_params = parse_auth_header(auth_header)
        if not verify_digest(method, auth_params):
            print(f" -> Auth FAILED for user '{extension}'")
            self.send_401_challenge(headers, sock, client_addr)
            return

        # Step 3: Success -> Store user address in memory
        print(f" -> Auth OK. Extension '{extension}' registered at {client_addr}")
        REGISTRY[extension] = client_addr

        contact = headers.get("Contact", "")
        response = (
            "SIP/2.0 200 OK\r\n"
            f"Via: {headers.get('Via')}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
            f"Call-ID: {headers.get('Call-Id')}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f"Contact: {contact}\r\n"
            "Expires: 3600\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(response.encode("utf-8"), client_addr)

    def send_401_challenge(self, headers, sock, client_addr):
        nonce = secrets.token_hex(16)
        challenge = (
            "SIP/2.0 401 Unauthorized\r\n"
            f"Via: {headers.get('Via')}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
            f"Call-ID: {headers.get('Call-Id')}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"\r\n'
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(challenge.encode("utf-8"), client_addr)

    def process_invite(self, raw_data, start_line, headers, call_id, sock, client_addr):
        target_user = extract_user(start_line.split()[1])

        if target_user not in REGISTRY:
            print(f" -> Extension '{target_user}' not online.")
            not_found = (
                "SIP/2.0 404 Not Found\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(not_found.encode("utf-8"), client_addr)
            return

        target_addr = REGISTRY[target_user]

        # Send 100 Trying to caller
        trying = (
            "SIP/2.0 100 Trying\r\n"
            f"Via: {headers.get('Via')}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(trying.encode("utf-8"), client_addr)

        # Track active call
        CALLS[call_id] = {"caller": client_addr, "callee": target_addr}
        # Relay INVITE to destination
        sock.sendto(raw_data.encode("utf-8"), target_addr)

    def handle_response(self, raw_data, start_line, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]
        dest = call["caller"] if client_addr == call["callee"] else call["callee"]
        sock.sendto(raw_data.encode("utf-8"), dest)

    def forward_in_dialog(self, raw_data, method, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]
        dest = call["callee"] if client_addr == call["caller"] else call["caller"]
        sock.sendto(raw_data.encode("utf-8"), dest)

        if method == "BYE":
            print(f" -> Call {call_id} hung up.")
            CALLS.pop(call_id, None)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 5060
    print(f"SIP Server running on UDP {HOST}:{PORT} (Realm: {REALM})")
    try:
        server = socketserver.ThreadingUDPServer((HOST, PORT), SIPHandler)
        server.serve_forever()
    except PermissionError:
        print("Error: Port 5060 requires root permissions. Use 'sudo' or set PORT=5061.")
    except KeyboardInterrupt:
        print("\nStopping SIP server.")
