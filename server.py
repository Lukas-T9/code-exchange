from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))[:32]

@app.route('/app', methods=['POST'])
def get_code():
    try:
        data = request.get_json()
        client_key = data['key']

        # Generate server-generated code
        code_to_execute = ""

        with open("your_text_file.py", "r") as file:
            code_to_execute = file.read()
        # Derive a key from the client's key
        derived_key = derive_key(client_key.encode(), b'salt')

        # Encrypt the code using the derived key
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(b'0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_code = base64.urlsafe_b64encode(encryptor.update(code_to_execute.encode()) + encryptor.finalize())

        # Send the encrypted code to the client
        return jsonify({'status': 'success', 'code': encrypted_code.decode()})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(port=5000)
