from http.server import HTTPServer, BaseHTTPRequestHandler
import json, hashlib, os, sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PHRASE = "d2caac68c555fa37e412171cd5240e2d0bb1bea23d4ccdb950157d37136ebcf46ed3263984d5ec5ffbb5cd4e7092b2c802b9d5a9c372c3492afa09eaf35fb9ac"

def ensure_ca():
    if not os.path.exists("ca_certs/intermediate_ca.crt"):
        os.makedirs("ca_certs", exist_ok=True)
        
        root_key = rsa.generate_private_key(65537, 2048)
        root_subject = x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "RU")])
        
        root_cert = x509.CertificateBuilder().subject_name(root_subject
        ).issuer_name(root_subject
        ).public_key(root_key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.utcnow()
        ).not_valid_after(datetime.utcnow() + timedelta(days=3650)
        ).add_extension(x509.BasicConstraints(ca=True, path_length=1), True
        ).sign(root_key, hashes.SHA256())
        
        with open("ca_certs/root_ca.crt", "wb") as f: f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        with open("ca_certs/root_ca.key", "wb") as f: f.write(root_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        
        intermediate_key = rsa.generate_private_key(65537, 2048)
        intermediate_cert = x509.CertificateBuilder().subject_name(root_subject
        ).issuer_name(root_subject
        ).public_key(intermediate_key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.utcnow()
        ).not_valid_after(datetime.utcnow() + timedelta(days=3650)
        ).add_extension(x509.BasicConstraints(ca=True, path_length=0), True
        ).sign(root_key, hashes.SHA256())
        
        with open("ca_certs/intermediate_ca.crt", "wb") as f: f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
        with open("ca_certs/intermediate_ca.key", "wb") as f: f.write(intermediate_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

def load_ca():
    ensure_ca()
    with open("ca_certs/intermediate_ca.crt", "rb") as f: ca_cert = x509.load_pem_x509_certificate(f.read())
    with open("ca_certs/intermediate_ca.key", "rb") as f: ca_key = serialization.load_pem_private_key(f.read(), None)
    return ca_cert, ca_key

def load_db():
    if os.path.exists("data/certificates.json"):
        with open("data/certificates.json", "r") as f: return json.load(f)
    return {}

def save_db(db):
    os.makedirs("data", exist_ok=True)
    with open("data/certificates.json", "w") as f: json.dump(db, f)

def verify_sig(pub_key_hex, sig_hex):
    try:
        pub_key = serialization.load_pem_public_key(bytes.fromhex(pub_key_hex.strip()))
        pub_key.verify(bytes.fromhex(sig_hex.strip()), PHRASE.encode(), padding.PKCS1v15(), hashes.SHA1())
        return True
    except: return False

def sign_csr(csr_pem, pub_key_hex):
    ca_cert, ca_key = load_ca()
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid: raise ValueError("Invalid CSR")
    
    cert = x509.CertificateBuilder().subject_name(csr.subject
    ).issuer_name(ca_cert.subject
    ).public_key(csr.public_key()
    ).serial_number(int(hashlib.sha256(pub_key_hex.encode()).hexdigest()[:16], 16)
    ).not_valid_before(datetime.utcnow()
    ).not_valid_after(datetime.utcnow() + timedelta(days=90)
    ).add_extension(x509.BasicConstraints(ca=False, path_length=None), True
    ).sign(ca_key, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM).decode()

class ACMEHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/sign':
            try:
                cl = int(self.headers.get('Content-Length', 0))
                xpk = self.headers.get('x-Public-Key')
                auth = self.headers.get('Authorization')
                
                if not xpk: self.send(400); return
                if not auth: self.send(401); return
                if not verify_sig(xpk, auth): self.send(403); return
                
                db = load_db()
                kh = hashlib.sha256(xpk.strip().encode()).hexdigest()
                if kh in db: self.send(409); return
                if cl == 0: self.send(400); return
                
                csr = self.rfile.read(cl)
                try: 
                    if not x509.load_pem_x509_csr(csr).is_signature_valid: self.send(400); return
                except: self.send(400); return
                
                cert = sign_csr(csr, xpk)
                db[kh] = {"public_key": xpk.strip(), "certificate": cert}
                save_db(db)
                
                self.send_response(201)
                self.send_header('Content-Type', 'application/x-pem-file')
                self.send_header('Content-Length', len(cert))
                self.end_headers()
                self.wfile.write(cert.encode())
            except: self.send(500)
        else: self.send(404)
    
    def do_GET(self):
        if self.path == '/verify':
            try:
                xpk = self.headers.get('x-Public-Key')
                if not xpk: self.send(400); return
                
                db = load_db()
                kh = hashlib.sha256(xpk.strip().encode()).hexdigest()
                if kh not in db: self.send(404); return
                
                cert = x509.load_pem_x509_certificate(db[kh]["certificate"].encode())
                resp = "TRUE" if cert.not_valid_after >= datetime.utcnow() else "FALSE"
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', len(resp))
                self.end_headers()
                self.wfile.write(resp.encode())
            except: self.send(500)
        else: self.send(404)
    
    def send(self, code):
        self.send_response(code)
        self.end_headers()
    
    def log_message(self, *args): pass

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("ca_certs", exist_ok=True)
    ensure_ca()
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    print(f"ACME Server on port {port}")
    HTTPServer(('0.0.0.0', port), ACMEHandler).serve_forever()