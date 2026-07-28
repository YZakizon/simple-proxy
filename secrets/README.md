# Local secrets

Create these files before starting the Compose service:

- `proxy_basic_auth`: one `username:password` value followed by a newline.
- `tls-cert.pem`: the TLS certificate chain.
- `tls-key.pem`: the TLS private key.

The directory contents are ignored by Git. Files must be readable by container
UID/GID `65532:65532`; keep them read-only and restrict host access.
