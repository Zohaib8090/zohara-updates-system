# Plan: turn zohara-updates-system into the Zohara release admin

Written 2026-10-01 after reading `src/main.rs` (866 lines), `Dockerfile`, the templates and the README, and
looking at the live service, the GitHub App and the pacman config shipped in the ISO. Nothing here has been
built yet. Nothing was changed in the running service.

## 1. What exists today

A small Rust web app (axum 0.7, askama, reqwest, jsonwebtoken) on Render, deployed from this repo. It authenticates
to GitHub as the GitHub App `zohara-updates-system` (App ID 4833498, installed on the whole `Zohaib8090` account)
by signing a JWT with the app's private key, which lives in the env var `ZOHARA_HUB_APP_PRIVATE_KEY` on Render.

| Route | What it does |
|---|---|
| `GET /` | lists two watched repos (`zohara-settings`, `zohara-apps`) |
| `GET /repo/{owner}/{name}` | lists the last 15 successful workflow runs, each with Publish to stable / beta / alpha buttons |
| `POST /publish` | takes the run's first artifact, unzips it, runs `repo-add`, uploads a new `zohara.db.tar.zst` and the package to the channel release in `zohara-packages`, records it in `apps.json` |
| `GET /health` | `ok` |

No database, no login, no state.

## 2. Problems found in the code

**Security (fix before anything else)**

1. **No login at all.** The live page lists the buttons to anyone. `POST /publish` is open too.
2. **`/publish` trusts the `repo` field from the form.** `do_publish` splits `f.repo` into owner and name and never
   checks it against `watched_repos`. Any repository the app is installed on works, including private ones, and
   any `run_id`. The run is not required to be successful, to be on `main`, or to come from a push (a pull-request
   run would be accepted).
3. **Unsigned packages go straight to every machine.** The installed `[zohara-stable]` section in
   `/etc/pacman.conf` has `SigLevel = Optional TrustAll` (see `zohara-profile/airootfs/root/customize_airootfs.sh`
   line 351), so pacman installs whatever is in the release. Points 1 and 2 together mean an outsider could get an
   artifact of their choosing installed as root on Zohara machines. The signed manifest does not cover this: it
   only pins the Arch snapshot date.
4. No CSRF protection, no rate limit, no audit trail.
5. The GitHub App has contents read and write on **all** repositories, but only `zohara-packages` needs write.
6. The app's private key was exposed in a chat on 2026-10-01 (the second of two keys on the app). It must be
   replaced and both old keys deleted.

**Correctness**

7. **Each publish replaces the package database with one that contains only that package.** `repo-add` runs in an
   empty temp directory, then the result is uploaded over the old database. Publishing `zohara-settings` removes
   every other package from the channel's database.
8. **Wrong file names for the installed systems.** It uploads `zohara.db.tar.zst`. Installed systems fetch
   `zohara-stable.db` (see GOTCHA.md, "pacman fetches `<section name>.db`"), and `zohara.files` is not produced.
   `zohara-packages/.github/workflows/publish.yml` has the right logic (`cp -L` copies for `zohara-$CHANNEL.db`).
9. `ensure_release` creates a missing release with `PUT`; GitHub wants `POST`, so a new channel would fail.
10. Takes `arts.artifacts.into_iter().next()`: whichever artifact is listed first, whatever its name.
11. Two publishes at once race each other (no lock). Whole artifacts are held in memory.
12. `apps.json` failures are only logged, so the record can silently drift.

## 3. Target design

One private admin site that does four jobs, always behind login:

1. **Promote packages**: pick a successful build, pick a channel, publish.
2. **Promote the ISO**: pick a successful ISO build artifact, publish to OCI (main) and SourceForge (mirror).
3. **Approve an update date**: sign the manifest (`approved_date`, held packages) with the minisign key.
4. **Roll back**: re-promote the previous good build or manifest.

### Login

GitHub OAuth through the same GitHub App ("Request user authorization"). The callback checks the **numeric GitHub
user id** of `Zohaib8090`, not the name, and rejects everyone else. Session cookie: signed, `HttpOnly`, `Secure`,
`SameSite=Strict`, short life. Every `POST` carries a CSRF token. Everything except `/health` and the OAuth callback
sits behind one middleware, so a forgotten route cannot be public. GitHub two-factor stays on.

### Who does the work

Recommended: the site decides and triggers, **GitHub Actions does the publishing** (a promote workflow in
`zohara-packages`, `concurrency: promote` so two runs queue). Reasons: secrets stay in Actions, there are logs and a
permanent record, nothing large passes through the Render free tier, and the working logic from `publish.yml`
(db merge, both file names, `cp -L`) is reused. The old in-service publish code is deleted. The site only needs
`actions: write` on `zohara-packages` plus read access to the source repos.

The existing `publish.yml` needs a fix first: its manual trigger has no `run_id` input, so it cannot take an
artifact from a build run.

### Storage

* Packages and update files: OCI Object Storage as main and GitHub Releases as mirror. Installed systems keep the
  GitHub URL in `/etc/pacman.conf`, so that URL must keep working until a Store update changes the server line.
* ISO: OCI (public bucket `zohara-os`, `ap-mumbai-1`, namespace `bm27e3oxmp04`) and SourceForge mirror, plus
  `SHA256SUMS`. GitHub cannot hold it (2 GB per file).
* OCI write access for the workflow: a dedicated OCI user that can only write to that bucket, its API key stored as
  an Actions secret. Decide before phase 3 (see section 5).

### Signing

* The manifest stays minisign (the Store verifies with the public key in `manifest.pub`).
* The key is stored **encrypted with minisign's own password protection** in a private OCI bucket, never in a
  public repo. On the admin page you type the password (long, random, kept in a password manager); the service
  signs in memory, never writes the password anywhere, and returns the signed manifest.
* Correction to what I said earlier: signing "in the browser so the server never sees the password" adds little,
  because the same server delivers the page's JavaScript. Signing in the service is simpler and no less safe. The
  protection that matters is: password never stored, key file private, login limited to you.
* The existing signing key is not on any machine we can find. If it stays lost, create a new key and ship the new
  `manifest.pub` in the next Store package and the ISO (only your own test machines trust the old one).
* Open gap: packages in `[zohara-stable]` are unsigned (point 3 above). Phase 5 closes it.

### Rollback and record

Keep the previous database and manifest as assets (`*.previous`). Every promotion appends one line to a
`promotions.json` in `zohara-packages` (who, what, run id, hash, time). The Rollback button re-promotes the previous
entry.

## 4. Phases (each has a check that must pass before the next)

| # | Work | Check |
|---|---|---|
| 0 | **You:** suspend the Render service now (it is open to the internet). | `https://zohara-updates-system.onrender.com/` no longer serves the buttons. |
| 1 | **Make it safe.** (**Coded and tested locally 2026-10-01, not deployed**: `src/auth.rs`, login middleware, CSRF, watched-repo allowlist, run checks, publishing off.) New GitHub App key; allowlisted repos only; run must be successful, on `main`, event `push`; login + CSRF middleware; restrict the app to the repos it needs. | Without a session, `POST /publish` and every page redirect or return 401; a forged `repo` is refused; test in code. |
| 2 | **Make it correct.** (**Done 2026-10-02**: `publish.yml` takes a run id, checks inputs and run, merges and re-checks the database, apps.json only on stable; the site starts it with a dispatch. Tested on alpha with real runs of both source repos; a real `pacman -Sl zohara-alpha` listed 6 packages. The site's Publish button was not clicked live yet.) Fix `publish.yml` to take a `run_id`; promote workflow merges into the existing db and writes `zohara-<channel>.db/.files`; site triggers it. Try on `alpha` only. | In the test VM, `pacman -Sy` against the alpha channel lists at least two packages after publishing both. |
| 3 | **Storage.** OCI as main, GitHub as mirror, for packages; ISO promote with `SHA256SUMS`. | Download from the public OCI URL and compare the hash to the build's. |
| 4 | **Signing page.** Encrypted key in a private bucket, password field, manifest signed and published. Decide key reuse versus new key. | A client check (`verify.yml` and the Store) accepts the new manifest; a wrong password signs nothing. |
| 5 | **Signed packages.** Create a Zohara signing key for pacman, sign the db and packages, move `[zohara-stable]` from `Optional TrustAll` to `Required` through a Store update. | An unsigned package is refused in the test VM. |
| 6 | **Rollback and record.** `promotions.json`, Rollback button. | Promote A then B, roll back, systems get A again. |
| 7 | **Retire.** Delete both old app keys, remove the old routes and `apps.json` handling, update the docs and handoff. | Nothing in GitHub or Render references the old keys. |

Phases 0 to 2 fix what is broken today. Phases 3 to 7 are the new features.

## 5. Decisions (answered 2026-10-01: suspend now, everything else "as you recommend")

1. Suspend the old service: **done**, Render answers 503 "Service Suspended".
2. The site triggers GitHub Actions; the workflow publishes.
3. A dedicated OCI user limited to the `zohara-os` bucket, API key as an Actions secret.
4. Signing key: keep looking on the Windows PC, otherwise create a new one in phase 4.
5. Signed packages (phase 5): yes.
6. Keep this repo.

(The original questions follow, for the record.)

## 5b. Questions as they were asked

1. **Suspend the old service now?** (Recommended: yes.)
2. **Who publishes:** the site triggers GitHub Actions (recommended) or the service does the work itself, as now.
3. **OCI credentials for the workflow:** OK to create a dedicated OCI user limited to the `zohara-os` bucket?
4. **Signing key:** keep looking for the old one, or create a new one now?
5. **Packages:** want signed packages (phase 5)? It is the real fix for unsigned installs and needs one Store update
   to roll out.
6. **Where the code lives:** keep this repo and Render service name, or start a new repo and keep this one as a
   reference until phase 7?

## 6. Reuse and rewrite

| Keep | Rewrite or delete |
|---|---|
| GitHub App JWT and installation-token code (`AppAuth`) | `do_publish` and everything it calls (replaced by the promote workflow) |
| `Gh` REST helper, `urlencode` | `ensure_release` (PUT bug), `update_apps_json` |
| askama templates and layout, `/health` | open routes (wrap them in the login middleware) |
| Dockerfile structure (Rust build, small runtime) | runtime image no longer needs `pacman`/`repo-add` once the workflow does the db work |
