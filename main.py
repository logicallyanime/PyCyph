from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64, sys

def encrypt_data(data: str, public_key: rsa.RSAPublicKey) -> str:
    data_bytes = data.encode()
    encrypted_bytes = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    base64.a85encode
    return base64.b64encode(encrypted_bytes).decode()

def main():

    if len(sys.argv) > 2:
        base64_str = sys.argv[2]
        b64_bytes = base64.b64decode(base64_str)
        public_key = serialization.load_pem_public_key(b64_bytes)
        print(encrypt_data(sys.argv[1], public_key))

    else:
        print("Usage: python3 main.py [data] [public_key]")
        return False



if __name__ == "__main__":
    main()

