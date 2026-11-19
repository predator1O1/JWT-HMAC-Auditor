# JWT-HMAC-Common

A medium-sized synthetic candidate list for authorized JWT HMAC secret audits and controlled labs.

## Contents
- `jwt-hmac-common.txt` — 850 unique candidate strings, exactly one candidate per line.
- Includes placeholder-style values, development/test labels, JWT/HMAC-related labels, generic application key names, and predictable formatting variants.
- Contains no leaked credential dumps, harvested secrets, or personal data.

## Intended use
Use only with JWTs and systems you own or are explicitly authorized to assess. This is a candidate list for offline signature verification, not a guarantee that a real signing key can be recovered.

## Construction and provenance
This list was assembled specifically for this project from synthetic, generic weak-secret patterns. It is not copied from RockYou, SecLists, Google-10000-English, or any leaked password corpus. Its ordering is not an empirically measured probability ranking.

Technical references:
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

These references provide security context; they are not sources of the candidate strings.

## Limitations
- A dictionary can only find a key if the exact candidate is present.
- Strong, randomly generated high-entropy keys should not be recoverable using this list.
- This list is not a substitute for reviewing key generation, storage, rotation, algorithm allowlisting, signature verification, or JWT claim validation.

## Integrity
- Candidate count: 850
- SHA-256: `9558c322fd3ed0b5e5625948bf5cd70b893f7b8b7c1b2a4a9e9c5b956eff1f03`

Verify on Windows:
```powershell
(Get-Content .\jwt-hmac-common.txt).Count
(Get-FileHash .\jwt-hmac-common.txt -Algorithm SHA256).Hash
```

## Licensing and attribution
The candidate strings were synthetically generated for this project. External standards and guidance remain the property of their respective publishers and are linked for reference. Linking these resources does not relicense their contents.
