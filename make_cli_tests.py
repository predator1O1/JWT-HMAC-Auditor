
#!/usr/bin/env python3

"""
Generate independent JWT test fixtures for CLI testing.
Uses Python standard library only.
"""

import base64
import hashlib
import hmac
import json
from pathlib import Path


OUTPUT = Path("cli_fixtures")

ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

DECOY_COUNT = 5000


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_token(algorithm, secret):
    header = {
        "alg": algorithm,
        "typ": "JWT"
    }

    payload = {
        "sub": "cli-test-user",
        "role": "security-tester",
        "algorithm_test": algorithm
    }

    header_part = b64url(
        json.dumps(header, separators=(",", ":")).encode()
    )

    payload_part = b64url(
        json.dumps(payload, separators=(",", ":")).encode()
    )

    signing_input = f"{header_part}.{payload_part}"

    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        ALGORITHMS[algorithm]
    ).digest()

    return f"{signing_input}.{b64url(signature)}"


def main():
    OUTPUT.mkdir(exist_ok=True)

    for algorithm in ALGORITHMS:

        secret = f"cli-test-secret-{algorithm}-2026"

        token = create_token(algorithm, secret)

        (OUTPUT / f"{algorithm}.jwt").write_text(
            token, encoding="utf-8"
        )

        wordlist_path = OUTPUT / f"{algorithm}.txt"

        with wordlist_path.open("w", encoding="utf-8") as file:

            for index in range(DECOY_COUNT):
                file.write(
                    f"decoy-{algorithm}-{index:06d}\n"
                )

            # Correct secret deliberately placed last.
            file.write(secret + "\n")

        print(f"[+] Generated {algorithm}")
        print(f"    JWT: {algorithm}.jwt")
        print(f"    Wordlist: {algorithm}.txt")
        print(f"    Candidates: {DECOY_COUNT + 1:,}")

    # Wrong-secret test fixture.
    (OUTPUT / "wrong_secret.txt").write_text(
        "incorrect-candidate-one\n"
        "incorrect-candidate-two\n"
        "incorrect-candidate-three\n",
        encoding="utf-8"
    )

    print("\n[+] All CLI test fixtures generated.")
    print(f"[+] Location: {OUTPUT.resolve()}")


if __name__ == "__main__":
    main()

