import secrets
import os

def generate_secret_key():
    return secrets.token_urlsafe(32)

def save_secret_key(key, filename='.env'):
    with open(filename, 'a') as f:
        f.write(f"\nJWT_SECRET_KEY={key}\n")

if __name__ == "__main__":
    key = generate_secret_key()
    save_secret_key(key)
    print(f"Secret key generated and saved to .env file: {key}")