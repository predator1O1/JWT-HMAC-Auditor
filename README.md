# JWT-HMAC-Auditor

A lightweight, dependency-free Python tool for offline auditing of JWT HMAC signing secrets using dictionary-based candidate verification.

JWT-HMAC-Auditor supports HS256, HS384, and HS512. It verifies candidate secrets against a JWT's signature and includes checkpointing functionality to support resuming interrupted scans.

## Features

- Supports JWT HMAC algorithms:
  - HS256
  - HS384
  - HS512
- Automatically detects the algorithm from the JWT header.
- Performs offline candidate-secret verification using a wordlist.
- Uses Python's standard library; no third-party dependencies required.
- Supports multithreaded candidate verification.
- Displays scan progress, elapsed time, speed, and estimated remaining time.
- Saves scan checkpoints and supports resuming interrupted scans.
- Validates checkpoint metadata before resuming.
- Uses constant-time signature comparison with `hmac.compare_digest`.
- Includes unit tests for core functionality.

## Requirements

- Python 3.10 or later recommended.
- A JWT signed using HS256, HS384, or HS512.
- A candidate wordlist.

No external Python packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/predator1O1/JWT-HMAC-Auditor.git
cd JWT-HMAC-Auditor
```

Run the tool:

```bash
python3 jwt_crack.py --help
```

## Usage

Basic scan:

```bash
python3 jwt_crack.py -t "JWT_TOKEN" -w wordlist.txt
```

Specify the number of workers:

```bash
python3 jwt_crack.py -t "JWT_TOKEN" -w wordlist.txt -c 10
```

Specify a checkpoint file:

```bash
python3 jwt_crack.py -t "JWT_TOKEN" -w wordlist.txt -c 10 --checkpoint scan.checkpoint.json
```

Resume an interrupted scan:

```bash
python3 jwt_crack.py -t "JWT_TOKEN" -w wordlist.txt --checkpoint scan.checkpoint.json --resume
```

Restart a scan from the beginning:

```bash
python3 jwt_crack.py -t "JWT_TOKEN" -w wordlist.txt --checkpoint scan.checkpoint.json --restart
```

Run `python3 jwt_crack.py --help` to view the available command-line options.

## Testing

Run the unit test suite:

```bash
python3 -m unittest discover -s tests -v
```

The current unit test suite covers:

- HS256, HS384, and HS512 verification.
- Incorrect candidate secrets.
- Invalid JWT formats.
- Unsupported algorithms.
- Signature length validation.
- Payload decoding.
- Checkpoint validation.
- Token and wordlist fingerprint mismatches.
- Invalid checkpoint metadata.

CLI regression checks should also be performed using the provided test fixtures.

## How It Works

1. Parses the JWT header, payload, and signature.
2. Identifies the supported HMAC algorithm.
3. Reads candidate secrets from the supplied wordlist.
4. Calculates an HMAC signature for each candidate.
5. Compares the calculated signature with the JWT signature.
6. Reports a matching candidate if one is found.
7. Saves checkpoint information to support resuming an interrupted scan.

## Important Limitations

- This is a dictionary-based auditing tool, not a universal JWT cracking solution.
- A candidate secret must be present in the supplied wordlist to be recovered.
- Strong, randomly generated secrets are generally impractical to recover through dictionary attacks.
- The tool performs offline signature verification; it does not test an application's complete JWT authentication or authorization implementation.
- It does not validate application-level claims such as issuer, audience, expiration, or authorization rules.

## Security and Authorized Use

This tool is intended for authorized security testing, controlled lab environments, and defensive auditing of JWT implementations.

Only test tokens and systems for which you have explicit permission.

The author is not responsible for misuse or unauthorized activity.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributions

Contributions, bug reports, and suggestions are welcome.