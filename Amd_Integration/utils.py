import base64
import hashlib
import secrets
import string
from django.conf import settings
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def generate_kid_from_key(key_path):
    with open(key_path, 'rb') as key_file:
        private_key_pem = key_file.read()

    private_key = load_pem_private_key(private_key_pem, password=None)
    numbers = private_key.private_numbers()
    modulus = numbers.public_numbers.n
    private_exponent = numbers.d
    key_material = modulus.to_bytes(
        (modulus.bit_length() + 7) // 8, byteorder='big')
    key_material += private_exponent.to_bytes(
        (private_exponent.bit_length() + 7) // 8, byteorder='big')

    digest = hashes.Hash(hashes.SHA384())
    digest.update(key_material)
    hash_digest = digest.finalize()

    return base64.urlsafe_b64encode(hash_digest).rstrip(b'=').decode('utf-8')


def load_key(key_path):
    with open(key_path, 'r') as key_file:
        return key_file.read()


def create_jwt(payload):
    private_key = load_key(settings.JWT_PRIVATE_KEY_PATH)
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token


def decode_jwt(token):
    public_key = load_key(settings.JWT_PUBLIC_KEY_PATH)
    try:
        decoded_payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return decoded_payload
    except jwt.ExpiredSignatureError:
        raise Exception('Token has expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')


def generate_code_verifier(length=64):
    """Generate a cryptographically secure random string for the code_verifier."""
    alphabet = string.ascii_letters + string.digits + '-._~'
    code_verifier = ''.join(secrets.choice(alphabet) for _ in range(length))
    return code_verifier


def generate_code_challenge(code_verifier):
    """Generate a code_challenge from the code_verifier using SHA-256."""
    # Hash the code_verifier using SHA-256
    hashed = hashlib.sha256(code_verifier.encode()).digest()
    # Encode the hash in Base64 URL format
    code_challenge = base64.urlsafe_b64encode(hashed).rstrip(b'=').decode()
    return code_challenge
