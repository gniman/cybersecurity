import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import time

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db" # Constant for the database file name



def generate_key() -> rsa.RSAPrivateKey:
    """Generates a new RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def setup_database():
    """Initializes the database connection and creates the keys table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Create the table using the required schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_private_key(private_key: PrivateKeyTypes, expires_in_seconds: int) -> int:
    """Saves a key to the database, serializing it to PEM format (BLOB) and storing expiration as a UNIX timestamp (INTEGER)."""
    # Serialize the key to store it as bytes (BLOB)
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Calculate expiration time as a UNIX timestamp
    exp_timestamp = int(time.time()) + expires_in_seconds

    # Insert the key using query parameters for security (SQL Injection prevention)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (pem_bytes, exp_timestamp)
    )
    kid = cursor.lastrowid
    conn.commit()
    conn.close()
    return kid

def load_private_key(expired: bool = False) -> tuple[int | None, PrivateKeyTypes | None]:
    """Retrieves a single key from the database, prioritizing valid or expired keys based on the flag."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(time.time())
    
    if expired:
        # Select one expired key
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1",
            (current_time,)
        )
    else:
        # Select one valid key
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp >= ? ORDER BY exp DESC LIMIT 1",
            (current_time,)
        )

    row = cursor.fetchone()
    conn.close()
    
    if row:
        kid, pem_bytes = row
        # Deserialize the key from PEM bytes back into a Python key object
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None
        )
        return kid, private_key
    
    return None, None

def load_valid_public_keys() -> dict:
    """Fetches all currently valid keys from the database and constructs the JWKS response format."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = int(time.time())
    
    # Select all non-expired keys
    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp >= ?",
        (current_time,)
    )

    jwks_keys = []
    for kid, pem_bytes in cursor.fetchall():
        # Deserialize the private key to get access to its public components
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None
        )
        public_numbers = private_key.public_key().public_numbers()
        
        # Build the standard JWK dictionary for the public key
        jwks_keys.append({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid), 
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e),
        })

    conn.close()
    return {"keys": jwks_keys}

def int_to_base64(value: int) -> str:
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


# --- HTTP Server Class ---

class MyServer(BaseHTTPRequestHandler):
    
    # Methods for unsupported HTTP verbs
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    # POST /auth Endpoint
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Check for the 'expired' query parameter
            use_expired_key = 'expired' in params

            # Load the appropriate key from the DB
            kid, signing_key = load_private_key(expired=use_expired_key)

            if not signing_key:
                # Error if no key is found
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Error: No suitable signing key found.")
                return

            # Use the DB-assigned kid in the JWT header
            headers = {
                "kid": str(kid)
            }
            
            token_payload = {
                "user": "username",
            }

            if use_expired_key:
                # Set JWT expiration to the past
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            else:
                # Set JWT expiration to the future
                token_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            
            # Sign the JWT with the retrieved key object
            encoded_jwt = jwt.encode(token_payload, signing_key, algorithm="RS256", headers=headers)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    # GET /.well-known/jwks.json Endpoint
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Load valid keys from the database for the JWKS response
            keys = load_valid_public_keys()
            
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return




if __name__ == "__main__":
    
    #  Initialize the Database and create the table upon startup
    print("Setting up database and table...")
    setup_database()

    
    # Key that expires in the future (valid)
    valid_key = generate_key()
    valid_kid = save_private_key(valid_key, expires_in_seconds=3600) # 1 hour
    print(f"Stored valid key with kid: {valid_kid}")

    # Key that expires in the past (expired)
    expired_key = generate_key()
    expired_kid = save_private_key(expired_key, expires_in_seconds=-1) # -1 second
    print(f"Stored expired key with kid: {expired_kid}")

    # Start the Web Server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"\nServer started http://{hostName}:{serverPort}")
    print("Press Ctrl+C to stop.")
    
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("\nServer stopped.")