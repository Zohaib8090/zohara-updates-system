# zohara-hub

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
export ZOHARA_HUB_APP_PRIVATE_KEY="$(cat ~/Downloads/zohara-hub.2026-09-04.private-key.pem)"
export ZOHARA_HUB_INSTALLATION_ID=78901234
cargo run --release
```

Open http://localhost:8080.

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
   - Name: `zohara-hub`
   - Homepage: `https://zohara-hub.onrender.com`
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
