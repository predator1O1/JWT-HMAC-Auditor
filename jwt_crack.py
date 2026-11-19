
#!/usr/bin/env python3

"""
JWT-HMAC-Auditor v1.2.1

Dependency-free offline JWT HMAC signature verification tool.

Supported algorithms:
    HS256
    HS384
    HS512

Features:
    - Automatic JWT algorithm detection
    - Multithreaded candidate verification
    - Progress indicator
    - Candidates-per-second measurement
    - Estimated completion time
    - Checkpoint and resume support
    - Checkpoint fingerprint validation
    - Decoded payload display

For authorized security assessments only.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# CONFIGURATION
# ============================================================

VERSION = "1.2.1"

ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

DEFAULT_THREADS = 10
DEFAULT_BATCH_SIZE = 1000

DEFAULT_CHECKPOINT = ".jwt_hmac_auditor.checkpoint.json"


# ============================================================
# JWT PROCESSING
# ============================================================

def decode_b64url(value):
    """Decode Base64URL encoded data."""

    padding = "=" * (-len(value) % 4)

    return base64.b64decode(
        value + padding,
        altchars=b"-_",
        validate=True
    )


def parse_token(token):
    """Parse JWT and automatically detect its algorithm."""

    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError(
            "Invalid JWT: expected three segments."
        )

    try:
        header = json.loads(
            decode_b64url(parts[0])
        )

        if not isinstance(header, dict):
            raise ValueError("JWT header must be a JSON object.")

        algorithm = header.get("alg")

        if algorithm not in ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm!r}. "
                "Supported: HS256, HS384, HS512."
            )

        signature = decode_b64url(parts[2])

        hash_function = ALGORITHMS[algorithm]

        if len(signature) != hash_function().digest_size:
            raise ValueError(
                "JWT signature length does not match algorithm."
            )

        signing_input = (
            parts[0] + "." + parts[1]
        ).encode("ascii")

        payload_segment = parts[1]

        return (
            algorithm,
            signing_input,
            signature,
            payload_segment
        )

    except (ValueError, binascii.Error, UnicodeError) as error:
        raise ValueError(
            f"JWT parsing failed: {error}"
        ) from error


def decode_payload(payload_segment):
    """Decode JWT payload after successful signature verification."""

    try:
        payload = json.loads(
            decode_b64url(payload_segment)
        )

        return json.dumps(
            payload,
            indent=4,
            ensure_ascii=False
        )

    except (
        ValueError,
        binascii.Error,
        UnicodeError
    ):
        return None


# ============================================================
# SIGNATURE VERIFICATION
# ============================================================

def verify_candidate(task):
    """Verify one candidate secret against the JWT signature."""

    signing_input, signature, secret, hash_function = task

    try:
        expected_signature = hmac.new(
            secret.encode("utf-8"),
            signing_input,
            hash_function
        ).digest()

        if hmac.compare_digest(
            expected_signature,
            signature
        ):
            return secret

    except (ValueError, UnicodeError):
        pass

    return None


# ============================================================
# WORDLIST PROCESSING
# ============================================================

def get_wordlist_metadata(path):
    """Calculate wordlist fingerprint and total line count."""

    digest = hashlib.sha256()
    total_lines = 0

    with open(path, "rb") as file:

        for line in file:
            digest.update(line)
            total_lines += 1

    return digest.hexdigest(), total_lines


def get_token_fingerprint(token):
    """Generate a fingerprint without storing the token."""

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================
# CHECKPOINT MANAGEMENT
# ============================================================

def save_checkpoint(path, data):
    """Save checkpoint atomically."""

    temporary = path + ".tmp"

    with open(
        temporary,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(data, file, indent=4)

        file.flush()
        os.fsync(file.fileno())

    os.replace(temporary, path)


def load_checkpoint(path):
    """Load and validate checkpoint JSON."""

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Invalid checkpoint structure.")

    return data


def validate_checkpoint(saved, expected, total):
    """Validate checkpoint version, fingerprints and index."""

    required_fields = (
        "version",
        "token_fingerprint",
        "wordlist_fingerprint",
        "algorithm",
        "next_index"
    )

    for field in required_fields:

        if field not in saved:
            raise ValueError(
                f"Checkpoint missing field: {field}"
            )

    for field in (
        "version",
        "token_fingerprint",
        "wordlist_fingerprint",
        "algorithm"
    ):

        if saved[field] != expected[field]:
            raise ValueError(
                f"Checkpoint mismatch: {field}. "
                "Use --restart for a fresh scan."
            )

    index = saved["next_index"]

    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or not 0 <= index <= total
    ):
        raise ValueError("Invalid checkpoint index.")

    return index


def cleanup_checkpoint(path):
    """Remove checkpoint and temporary files."""

    for target in (path, path + ".tmp"):

        if os.path.exists(target):
            os.remove(target)


# ============================================================
# DISPLAY AND PROGRESS
# ============================================================

def format_time(seconds):
    """Format seconds into HH:MM:SS."""

    seconds = max(0, int(seconds))

    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def show_banner(algorithm, threads, batch_size, total, start_index):

    print("\n" + "=" * 48)
    print(f"          JWT-HMAC-Auditor v{VERSION}")
    print("=" * 48)

    print(f"Algorithm       : {algorithm}")
    print(f"Threads         : {threads}")
    print(f"Batch size      : {batch_size}")
    print(f"Total candidates: {total:,}")
    print(f"Resume index    : {start_index:,}")
    print("Dependencies    : None")

    print("=" * 48 + "\n")


def show_progress(tested, total, speed, elapsed):

    percentage = (
        tested / total * 100
        if total else 100
    )

    remaining = max(0, total - tested)

    eta = (
        remaining / speed
        if speed > 0 else 0
    )

    bar_width = 25

    filled = int(
        bar_width * percentage / 100
    )

    bar = (
        "#" * filled
        + "-" * (bar_width - filled)
    )

    print(
        f"\r[{bar}] "
        f"{percentage:6.2f}% | "
        f"{tested:,}/{total:,} | "
        f"{speed:,.0f} candidates/sec | "
        f"ETA {format_time(eta)} | "
        f"Elapsed {format_time(elapsed)}",
        end="",
        flush=True
    )


def display_match(secret, algorithm, payload_segment):

    print("\n\n[+] MATCH FOUND!")

    print(f"[+] Algorithm: {algorithm}")
    print(f"[+] Secret: {secret}")

    payload = decode_payload(payload_segment)

    if payload is not None:

        print("[+] Decoded payload:")
        print(payload)

    else:

        print("[!] Payload is not valid JSON.")


# ============================================================
# MAIN SCAN ENGINE
# ============================================================

def run_scan(args):

    algorithm, signing_input, signature, payload_segment = (
        parse_token(args.token)
    )

    wordlist_hash, total = get_wordlist_metadata(
        args.wordlist
    )

    token_hash = get_token_fingerprint(
        args.token
    )

    checkpoint_data = {
        "version": VERSION,
        "token_fingerprint": token_hash,
        "wordlist_fingerprint": wordlist_hash,
        "algorithm": algorithm,
        "next_index": 0
    }

    start_index = 0

    # Resume existing scan.

    if args.resume:

        if not os.path.isfile(args.checkpoint):
            raise ValueError("Checkpoint file not found.")

        saved = load_checkpoint(args.checkpoint)

        start_index = validate_checkpoint(
            saved,
            checkpoint_data,
            total
        )

    show_banner(
        algorithm,
        args.threads,
        args.batch_size,
        total,
        start_index
    )

    if start_index == total:

        print("[!] Checkpoint indicates all candidates were processed.")

        cleanup_checkpoint(args.checkpoint)
        return

    tested = start_index
    batch_start = start_index

    started = time.monotonic()
    found = False

    hash_function = ALGORITHMS[algorithm]

    try:

        with open(
            args.wordlist,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as wordlist:

            # Skip previously processed candidates.

            for _ in range(start_index):
                wordlist.readline()

            with ThreadPoolExecutor(
                max_workers=args.threads
            ) as pool:

                while tested < total:

                    batch_start = tested

                    batch = []

                    batch_limit = min(
                        args.batch_size,
                        total - tested
                    )

                    for _ in range(batch_limit):

                        line = wordlist.readline()

                        if not line:
                            break

                        batch.append(
                            line.rstrip("\r\n")
                        )

                    if not batch:
                        break

                    # Save beginning of current batch.
                    # Interrupted batches will be repeated.

                    checkpoint_data["next_index"] = batch_start

                    save_checkpoint(
                        args.checkpoint,
                        checkpoint_data
                    )

                    tasks = [
                        (
                            signing_input,
                            signature,
                            secret,
                            hash_function
                        )
                        for secret in batch
                    ]

                    futures = [
                        pool.submit(
                            verify_candidate,
                            task
                        )
                        for task in tasks
                    ]

                    for future in as_completed(futures):

                        result = future.result()

                        tested += 1

                        elapsed = (
                            time.monotonic() - started
                        )

                        speed = (
                            (tested - start_index) / elapsed
                            if elapsed > 0 else 0
                        )

                        show_progress(
                            tested,
                            total,
                            speed,
                            elapsed
                        )

                        if result is not None:

                            found = True

                            for pending in futures:
                                pending.cancel()

                            display_match(
                                result,
                                algorithm,
                                payload_segment
                            )

                            break

                    if found:
                        break

                    # Commit completed batch.

                    checkpoint_data["next_index"] = (
                        batch_start + len(batch)
                    )

                    save_checkpoint(
                        args.checkpoint,
                        checkpoint_data
                    )

    except KeyboardInterrupt:

        checkpoint_data["next_index"] = batch_start

        save_checkpoint(
            args.checkpoint,
            checkpoint_data
        )

        print("\n\n[!] Scan interrupted.")
        print(f"[*] Resume index: {batch_start}")
        print(f"[*] Checkpoint: {args.checkpoint}")
        print("[*] Use --resume to continue.")

        raise

    # Successful match or completed scan:
    # checkpoint is no longer required.

    if found or tested >= total:
        cleanup_checkpoint(args.checkpoint)

    elapsed = time.monotonic() - started

    speed = (
        (tested - start_index) / elapsed
        if elapsed > 0 else 0
    )

    print("\n\n" + "=" * 48)

    if found:

        print("[+] Verification successful.")

    elif tested >= total:

        print("[-] No matching secret found.")

    else:

        print("[!] Scan ended before completion.")

    print(f"Candidates processed: {tested - start_index:,}")
    print(f"Average speed       : {speed:,.0f}/sec")
    print(f"Elapsed time        : {format_time(elapsed)}")

    print("=" * 48)


# ============================================================
# ARGUMENT PARSER
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            f"JWT-HMAC-Auditor v{VERSION} "
            "- Dependency-free JWT HMAC verification"
        )
    )

    parser.add_argument(
        "-t",
        "--token",
        required=True,
        help="JWT token"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Candidate wordlist path"
    )

    parser.add_argument(
        "-c",
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Worker threads (default: {DEFAULT_THREADS})"
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Candidates per batch (default: {DEFAULT_BATCH_SIZE})"
    )

    parser.add_argument(
        "--checkpoint",
        default=DEFAULT_CHECKPOINT,
        help="Checkpoint file path"
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume interrupted scan"
    )

    parser.add_argument(
        "--restart",
        action="store_true",
        help="Start a fresh scan"
    )

    return parser


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    if args.threads < 1:
        parser.error("Threads must be at least 1.")

    if args.batch_size < 1:
        parser.error("Batch size must be at least 1.")

    if args.resume and args.restart:
        parser.error(
            "--resume and --restart cannot be combined."
        )

    if not os.path.isfile(args.wordlist):
        parser.error("Wordlist file does not exist.")

    if os.path.abspath(args.wordlist) == os.path.abspath(args.checkpoint):
        parser.error("Checkpoint cannot overwrite the wordlist.")

    try:

        if args.restart:
            cleanup_checkpoint(args.checkpoint)

        run_scan(args)

    except KeyboardInterrupt:

        sys.exit(130)

    except (ValueError, OSError, binascii.Error) as error:

        print(f"\n[!] Error: {error}", file=sys.stderr)

        sys.exit(1)


if __name__ == "__main__":
    main()
