import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

def make_jwks_server(kid="test-key"):
    # cryptography's rsa module directly: PyJWT >= 2.13 removed
    # RSAAlgorithm.generate_private_key().
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    pub.update({"kid": kid, "use": "sig", "alg": "RS256"})
    jwks = {"keys": [pub]}
    holder = {"server": None}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    holder.update(server=srv, key=key, url=f"http://127.0.0.1:{srv.server_port}/certs", kid=kid)
    return holder

def mint(holder, claims, kid=None):
    return jwt.encode(claims, holder["key"], algorithm="RS256", headers={"kid": kid or holder["kid"]})
