# Internal deployment

Use `docker compose` with credentials and TLS material supplied as files. Do
not pass credentials on the command line.

```sh
cp .env.example .env
mkdir -p secrets
printf '%s\n' 'proxy-user:replace-with-a-long-random-password' \
  > secrets/proxy_basic_auth
cp /secure/source/fullchain.pem secrets/tls-cert.pem
cp /secure/source/privkey.pem secrets/tls-key.pem
chmod 600 secrets/*
docker compose up --build -d
```

The container runs as UID/GID `65532`. Ensure the three secret files are
readable by that identity using narrowly scoped ownership or ACLs. Compose
publishes only on `127.0.0.1` unless `PROXY_PUBLISH_ADDRESS` is deliberately
changed.
