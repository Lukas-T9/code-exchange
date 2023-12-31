import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

url = "http://127.0.0.1:5000/app"

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))[:32]


# Generate a random key for each request
client_key = base64.urlsafe_b64encode(os.urandom(32))

# Send the client key to the server
response = httpx.post(url, json={'key': client_key.decode()})
# Handle the response from the server
if response.status_code == 200 and 'code' in response.json():
    encrypted_code = response.json()['code']

    # Derive a key from the client's key
    derived_key = derive_key(client_key, b'salt')

    # Decrypt the code using the derived key
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(b'0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_code = decryptor.update(base64.urlsafe_b64decode(encrypted_code)) + decryptor.finalize()

    # Execute the decrypted code
    exec(decrypted_code)
else:
    print(f"Server returned an error: {response.status_code}, {response.json()}")
