# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately:

- Email: <dev@amsys.cz>
- Or use GitHub's private vulnerability reporting on this repository
  ("Security" tab → "Report a vulnerability"), if enabled.

Include the version or commit, a description, and steps to reproduce.
You will get an acknowledgement within 7 days.

## Scope

s3armor is a cryptographic proxy. Reports of most interest:

- Plaintext or key material reaching the backend or the logs.
- AEAD misuse: nonce reuse, missing or wrong AAD, truncation not detected.
- SigV4 verification bypass on the inbound (client) side.
- Parser crashes or memory exhaustion in the untrusted-input paths
  (the v1 frame/footer decoders, aws-chunked decoder, SigV4 header
  parsers — the four fuzz targets).

## Supported versions

Only the latest release receives security fixes.
