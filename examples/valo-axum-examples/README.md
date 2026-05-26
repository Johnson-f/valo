# valo-axum demo server

A runnable example that mounts the full `valo-axum` router (nested under `/auth`)
over a real `valo-core` engine. Emails are printed to the server console (see
`StdoutMailer`), so you can complete the signup → verify → signin flow entirely
from the terminal.

## Feature examples

Each file under `examples/` is a focused, runnable demonstration of one valo
feature. Most are **self-verifying**: they spin up the real router on an
ephemeral port, drive it, assert every step, and exit non-zero on failure.

Start the throwaway containers first (Postgres :5440, Redis :6390):

    docker start valo-postgres valo-redis

| Example | What it shows | Self-verifying | Run |
| --- | --- | --- | --- |
| `password_flow` | signup → verify → signin → refresh (rotation) → reuse-rejection → signout | yes | `cargo run -p valo-axum-examples --example password_flow` |
| `cookie_mode` | HttpOnly cookie token delivery; protected route via cookie | yes | `cargo run -p valo-axum-examples --example cookie_mode` |
| `rate_limiting` | per-IP limiter trips a 429 before password hashing | yes¹ | `cargo run -p valo-axum-examples --example rate_limiting` |
| `strict_revocation` | strict verify + `signout_all` instant revocation | yes | `cargo run -p valo-axum-examples --example strict_revocation` |
| `mfa_totp` | TOTP enroll → confirm → MFA-gated signin → complete | yes | `cargo run -p valo-axum-examples --example mfa_totp` |
| `eddsa_signing` | EdDSA-signed sessions (asymmetric keypair) | yes | `cargo run -p valo-axum-examples --example eddsa_signing` |
| `custom_templates` | branded email templates + `with_templates` | yes | `cargo run -p valo-axum-examples --example custom_templates` |
| `oauth_providers` | Google/GitHub wiring; live browser click-through | no² | `cargo run -p valo-axum-examples --example oauth_providers` |
| `mailer_providers` | construct Resend/SendGrid/SES/SMTP mailers | no³ | `cargo run -p valo-axum-examples --example mailer_providers --features resend` |

¹ Re-running within the 60s rate-limit window can pre-trip the limiter; flush
the throwaway Redis between local runs: `docker exec valo-redis redis-cli FLUSHALL`.
² Needs real OAuth credentials + a browser; prints guidance and exits cleanly
without them.
³ Needs provider feature flags (`--features resend|sendgrid|ses|smtp`) and real
keys to send; the example only constructs the providers.

## Prerequisites

Postgres and Redis must be reachable at the URLs in the workspace `.cargo/config.toml`
(`DATABASE_URL` = `postgres://valo:valo@127.0.0.1:5440/valo`, `REDIS_URL` = `redis://127.0.0.1:6390`).
The throwaway dev containers:

```bash
docker start valo-postgres valo-redis
# or first-time:
# docker run -d --name valo-postgres -e POSTGRES_USER=valo -e POSTGRES_PASSWORD=valo -e POSTGRES_DB=valo -p 5440:5432 postgres:17-alpine
# docker run -d --name valo-redis -p 6390:6379 redis:7-alpine
```

## Run

```bash
cargo run -p valo-axum-examples
# valo-axum demo listening on http://127.0.0.1:4000
# (set PORT=xxxx to use a different port)
```

## Walkthrough (bearer-token mode)

All endpoints are under `/auth`. Use `127.0.0.1` rather than `localhost` to avoid
IPv6/`::1` surprises.

```bash
# 1. Sign up -> 204. The verification link is printed in the SERVER console
#    (and points at this server because base_url matches the port).
curl -i -XPOST 127.0.0.1:4000/auth/signup \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"hunter2hunter2"}'

# 2. Open / curl the exact link the server printed -> 204.
curl -i "127.0.0.1:4000/auth/verify?token=PASTE_TOKEN_FROM_SERVER_CONSOLE"

# 3. Sign in -> 200 with JSON tokens.
curl -i -XPOST 127.0.0.1:4000/auth/signin \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"hunter2hunter2"}'
# {"access_token":"eyJ...","refresh_token":"...","access_expires_in":900}

# 4. Call a protected route with the access token -> 204.
curl -i -XPOST 127.0.0.1:4000/auth/signout-all \
  -H 'authorization: Bearer PASTE_ACCESS_TOKEN'

# 5. Rotate the refresh token -> 200 with a new pair (old one is now dead).
curl -i -XPOST 127.0.0.1:4000/auth/refresh \
  -H 'content-type: application/json' \
  -d '{"refresh_token":"PASTE_REFRESH_TOKEN"}'
```

### Things to try

- **Rate limiting**: repeat step 3 with a wrong password many times → eventually `429 Too Many Attempts`.
- **Unverified gate**: sign up, then sign in *before* verifying → `403 email is not verified`.
- **MFA**: as a signed-in user, `POST /auth/mfa/enroll` (Bearer token) returns an `otpauth_url`; scan it with an authenticator app, `POST /auth/mfa/confirm {"code":"123456"}` to get recovery codes, then a subsequent `/auth/signin` returns `{"mfa_required":true,"mfa_token":"..."}` to complete via `POST /auth/mfa/complete`.
- **Cookie mode**: change `TokenDelivery::Bearer` to `TokenDelivery::Cookie` in `src/main.rs`; signin then sets `valo_access`/`valo_refresh` HttpOnly cookies (`curl --cookie-jar /tmp/j.txt` / `--cookie /tmp/j.txt` carries them).
- **OAuth**: requires real Google/GitHub client credentials and a registered callback; wire a provider on the `Valo::builder()` and hit `GET /auth/oauth/{provider}`.
