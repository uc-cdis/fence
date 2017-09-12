from cryptography.fernet import Fernet


JWT_SECRET_KEY = 'secret_key'
DB = 'postgresql://postgres@localhost:5432/test_fence'
HMAC_ENCRYPTION_KEY = Fernet.generate_key()
