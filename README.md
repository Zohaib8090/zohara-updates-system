# zohara-updates-system

Tiny Rust web dashboard that watches our package-building repos
(`zohara-settings`, `zohara-store`, `zohara-apps`) and lets you
re-publish their artifacts to the OTA channel releases in
`Zohaib8090/zohara-packages` with one click.

Since phase 2 (2026-10-02) the dashboard no longer publishes anything itself. Pressing a Publish button checks
the request (watched repository, successful `main` build, artifact still there) and starts the `publish.yml`
workflow in `Zohaib8090/zohara-packages` with a `repository_dispatch`; that workflow does the download,
`repo-add`, upload and `apps.json` update (see that repo's README). You can follow it on the Actions page. The
old in-service publisher wiped the database each time and is gone.

No database, no persistent state — every page is a fresh GET.

## Sign-in (since 2026-10-01)

Every page except `/health`, `/login` and `/auth/callback` needs a GitHub sign-in, and only one numeric GitHub user
id gets in. Publishing only works when `ZOHARA_HUB_PUBLISH_ENABLED=1`. See [docs/PLAN.md](docs/PLAN.md).

| Env var | What |
|---|---|
| `ZOHARA_HUB_APP_ID`, `ZOHARA_HUB_INSTALLATION_ID`, `ZOHARA_HUB_APP_PRIVATE_KEY` | the GitHub App (reads runs and artifacts) |
| `ZOHARA_HUB_CLIENT_ID`, `ZOHARA_HUB_CLIENT_SECRET` | the same App's OAuth credentials (for sign-in) |
| `ZOHARA_HUB_ALLOWED_USER_ID` | numeric id of the only account allowed in (`gh api users/Zohaib8090 --jq .id`) |
| `ZOHARA_HUB_SESSION_SECRET` | 32+ random characters that sign the session cookie |
| `ZOHARA_HUB_BASE_URL` | the public address, no trailing slash (for the OAuth callback) |
| `ZOHARA_HUB_PUBLISH_ENABLED` | `1` to allow `/publish` (it starts the publish workflow; unset = look only) |
| `ZOHARA_HUB_SELF_PING` | `0` to turn off the keep-awake ping (on by default; see below) |

In the GitHub App's settings add the **Callback URL** `<ZOHARA_HUB_BASE_URL>/auth/callback` and generate a client
secret. Never put these values in the repo. Cookies are `Secure`, so sign-in only works over https (Render, or
a local https proxy).

## Keeping it awake on Render's free plan

Free web services sleep after 15 minutes without requests. The app calls its own public `/health` (from
`ZOHARA_HUB_BASE_URL`) every 10 minutes so Render sees traffic. Limits: it cannot wake a service that is already
asleep or suspended, and one always-on service uses about 730 of the 750 free instance hours a month, so it
leaves almost no room for a second always-on free service in the same workspace. If it still goes down, check
the service's Logs on Render: a crash at startup (missing environment variable) looks the same as sleeping.

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
