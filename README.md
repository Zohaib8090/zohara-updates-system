# zohara-updates-system

Tiny Rust web dashboard that watches our package-building repos
(`zohara-settings`, `zohara-store`, `zohara-apps`) and lets you
re-publish their artifacts to the OTA channel releases in
`Zohaib8090/zohara-packages` with one click.

Replaces the broken cross-repo GitHub Actions dispatch loop we kept
fighting. The dashboard calls the GitHub REST API directly:
downloads the `.pkg.tar.zst` artifact from the latest successful
build, runs `repo-add`, uploads the new `zohara.db` to the channel
release, and commits `apps.json` back.

No database, no persistent state — every page is a fresh GET.

## Sign-in (since 2026-10-01)

Every page except `/health`, `/login` and `/auth/callback` needs a GitHub sign-in, and only one numeric GitHub user
id gets in. **Publishing is switched off** (`ZOHARA_HUB_PUBLISH_ENABLED` unset) until phase 2 of
[docs/PLAN.md](docs/PLAN.md): the old publish code replaces the whole package database. Read the plan before
turning it on.

| Env var | What |
|---|---|
| `ZOHARA_HUB_APP_ID`, `ZOHARA_HUB_INSTALLATION_ID`, `ZOHARA_HUB_APP_PRIVATE_KEY` | the GitHub App (reads runs and artifacts) |
| `ZOHARA_HUB_CLIENT_ID`, `ZOHARA_HUB_CLIENT_SECRET` | the same App's OAuth credentials (for sign-in) |
| `ZOHARA_HUB_ALLOWED_USER_ID` | numeric id of the only account allowed in (`gh api users/Zohaib8090 --jq .id`) |
| `ZOHARA_HUB_SESSION_SECRET` | 32+ random characters that sign the session cookie |
| `ZOHARA_HUB_BASE_URL` | the public address, no trailing slash (for the OAuth callback) |
| `ZOHARA_HUB_PUBLISH_ENABLED` | `1` to allow `/publish` (leave unset for now) |

In the GitHub App's settings add the **Callback URL** `<ZOHARA_HUB_BASE_URL>/auth/callback` and generate a client
secret. Never put these values in the repo. Cookies are `Secure`, so sign-in only works over https (Render, or
a local https proxy).

## Run the tests

```bash
cargo test
```

The tests cover the session cookie (forged, expired, wrong user, wrong key) and which workflow runs may be
published. The route checks (no cookie, wrong cookie, wrong CSRF token, unwatched repo) were run by hand against a
local build on 2026-10-01; see docs/PLAN.md, phase 1.

## Deploy to Render free

1. Push this repo to GitHub.
2. On Render: **New → Web Service → pick the repo**.
3. Environment: **Docker**. (The Dockerfile builds an `archlinux:latest`
   image with `pacman` preinstalled.)
4. Plan: **Free**.
5. Set the env vars `ZOHARA_HUB_APP_ID`, `ZOHARA_HUB_APP_PRIVATE_KEY`
   (paste the whole PEM), and `ZOHARA_HUB_INSTALLATION_ID` from your
   Zohara GitHub App's installation.
6. Deploy. The dashboard lives at `https://<service-name>.onrender.com`.

## GitHub App setup (one-time)

1. https://github.com/settings/apps/new — create a new GitHub App:
   - Name: `zohara-updates-system`
   - Homepage: `https://zohara-updates-system.onrender.com`
   - Webhook: **disabled** (we don't receive webhooks)
   - Repository permissions:
     - **Contents**: Read & write (to commit `apps.json`)
     - **Metadata**: Read-only
   - Click "Create"
2. Generate a private key. Save the .pem file.
3. Install the app on `Zohaib8090/zohara-packages` (and on each of the
   watched source repos so it can read their workflow artifacts).
4. Note the **App ID** (Settings → General) and the **Installation ID**
   (URL of the install page, the trailing number).
5. Set those as the three env vars above.

## Layout

- `src/main.rs` — Axum server, GitHub App auth, the GET + publish logic.
- `templates/index.hbs`, `templates/repo.hbs` — Handlebars HTML.
- `Dockerfile` — multi-stage build, runtime uses `archlinux:latest` so
  `repo-add` is available.
