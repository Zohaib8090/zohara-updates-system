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

## Run locally

```bash
export ZOHARA_HUB_APP_ID=123456
export ZOHARA_HUB_APP_PRIVATE_KEY="$(cat ~/Downloads/zohara-updates-system.2026-09-04.private-key.pem)"
export ZOHARA_HUB_INSTALLATION_ID=78901234
# Every route (including POST /publish) requires HTTP Basic auth with
# these. There is no default -- the process refuses to start without
# them, since this dashboard can push a package into the OTA channel
# real installs pull updates from.
export ZOHARA_HUB_ADMIN_USER=zohaib
export ZOHARA_HUB_ADMIN_PASS="pick something long"
cargo run --release
```

Open http://localhost:8080 (your browser will prompt for the Basic auth
credentials above).

## Deploy to Render free

1. Push this repo to GitHub.
2. On Render: **New → Web Service → pick the repo**.
3. Environment: **Docker**. (The Dockerfile builds an `archlinux:latest`
   image with `pacman` preinstalled.)
4. Plan: **Free**.
5. Set the env vars `ZOHARA_HUB_APP_ID`, `ZOHARA_HUB_APP_PRIVATE_KEY`
   (paste the whole PEM), `ZOHARA_HUB_INSTALLATION_ID` from your Zohara
   GitHub App's installation, and `ZOHARA_HUB_ADMIN_USER` /
   `ZOHARA_HUB_ADMIN_PASS` (pick your own -- these gate every route on this
   service with HTTP Basic auth once it's live on the public internet).
6. Deploy. The dashboard lives at `https://<service-name>.onrender.com`.

## GitHub App setup (one-time)

1. https://github.com/settings/apps/new — create a new GitHub App:
   - Name: `zohara-updates-system`
   - Homepage: `https://zohara-updates-system.onrender.com`
   - Webhook: **disabled** (we don't receive webhooks)
   - Repository permissions:
     - **Contents**: Read & write (to commit `apps.json` and upload release assets)
     - **Actions**: Read-only (to list workflow runs and download their artifacts)
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
