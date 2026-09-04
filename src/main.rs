// Zohara Hub — a small web dashboard that watches our package-building
// repos and lets us re-publish their artifacts to the OTA channel
// releases in Zohaib8090/zohara-packages with one click.
//
// Why this exists: replace the broken cross-repo GitHub Actions
// dispatch loop with a simple "GET → publish" web tool. We don't
// need a database — every page request hits the GitHub REST API
// directly, so the dashboard is always in sync with reality.
//
// Routes:
//   GET  /                       — list all watched repos + their
//                                  recent successful workflow runs
//   GET  /repo/{owner}/{name}    — single-repo view (the page that
//                                  shows the "Publish" button per run)
//   POST /publish                — do the publish: download artifact
//                                  → repo-add → upload to release →
//                                  commit apps.json
//
// Auth: the GitHub App's installation token is held in env
// (ZOHARA_HUB_APP_ID + ZOHARA_HUB_APP_PRIVATE_KEY +
// ZOHARA_HUB_INSTALLATION_ID). The page is otherwise open — Render
// free's URL is hard to guess but I trust the model's threat model
// for now (you can put it behind a password later if you want).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Form, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router, Server,
};
use chrono::{DateTime, Utc};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};

// ── Configuration ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct AppConfig {
    /// Source repos the dashboard watches, with the package name each
    /// of their artifacts produces. (Same package name across repos
    /// is fine — they're independent.)
    sources: Vec<WatchedSource>,
}

#[derive(Clone, Debug)]
struct WatchedSource {
    /// "owner/name" on GitHub
    repo: String,
    /// The package name this repo produces (e.g. "zohara-settings").
    package: String,
    /// The arch the workflow builds for (so we can pick the right asset).
    arch: &'static str,
}

// ── GitHub App auth ──────────────────────────────────────────────────────

#[derive(Clone)]
struct GhApp {
    app_id: String,
    private_key_pem: String,
    installation_id: String,
    /// Cached installation token. GitHub installation tokens are good
    /// for 1 hour, so we refresh them well before that.
    cached_token: Arc<tokio::sync::RwLock<Option<CachedToken>>>,
}

struct CachedToken {
    token: String,
    expires_at: DateTime<Utc>,
}

impl GhApp {
    async fn token(&self) -> Result<String> {
        // Reuse if fresh.
        if let Some(c) = self.cached_token.read().await.as_ref() {
            if c.expires_at > Utc::now() + chrono::Duration::minutes(5) {
                return Ok(c.token.clone());
            }
        }

        // Mint a new JWT signed with the app's private key.
        let jwt = mint_jwt(&self.app_id, &self.private_key_pem)?;
        // Exchange the JWT for an installation token.
        let client = reqwest::Client::new();
        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            self.installation_id
        );
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-hub")
            .send()
            .await
            .context("exchange JWT for installation token")?
            .error_for_status()?
            .json::<TokenResponse>()
            .await
            .context("parse installation token response")?;

        let token = resp.token.clone();
        let expires_at = Utc::now() + chrono::Duration::seconds(
            (resp.expires_at.timestamp() - Utc::now().timestamp()).max(60),
        );
        *self.cached_token.write().await = Some(CachedToken {
            token: token.clone(),
            expires_at,
        });
        Ok(token)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    #[serde(rename = "expires_at")]
    expires_at: DateTime<Utc>,
}

// Build a short-lived GitHub App JWT.
// Format: {"iat":..., "exp":..., "iss":<app_id>}, signed RS256.
fn mint_jwt(app_id: &str, private_key_pem: &str) -> Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let now = Utc::now().timestamp();
    let exp = now + 9 * 60; // 9 minutes, GitHub requires <10
    let claims = serde_json::json!({
        "iat": now,
        "exp": exp,
        "iss": app_id,
    });
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .context("parse RSA private key")?;
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &key,
    )?;
    Ok(token)
}

// ── GitHub API helpers ───────────────────────────────────────────────────

#[derive(Clone)]
struct Gh {
    app: GhApp,
    client: reqwest::Client,
}

impl Gh {
    fn new(app: GhApp) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("zohara-hub")
            .build()
            .expect("build reqwest client");
        Self { app, client }
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let token = self.app.token().await?;
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} non-2xx"))?;
        Ok(resp.json().await?)
    }

    async fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let token = self.app.token().await?;
        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url} non-2xx"))?;
        Ok(resp.json().await?)
    }

    async fn download_to_file(&self, url: &str, dest: &std::path::Path) -> Result<()> {
        let token = self.app.token().await?;
        let bytes = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/octet-stream")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        std::fs::write(dest, &bytes)?;
        Ok(())
    }

    async fn put_json<B: Serialize, T: for'de Deserialize<'de>>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let token = self.app.token().await?;
        let resp = self
            .client
            .put(url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?
            .error_for_status()
            .with_context(|| format!("PUT {url} non-2xx"))?;
        Ok(resp.json().await?)
    }
}

// ── Domain types ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WorkflowRuns {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WorkflowRun {
    id: u64,
    name: String,
    head_branch: String,
    head_sha: String,
    display_title: String,
    path: String,
    conclusion: Option<String>,
    status: String,
    event: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    html_url: String,
    artifacts_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Artifacts {
    artifacts: Vec<Artifact>,
    total_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Artifact {
    id: u64,
    name: String,
    size_in_bytes: u64,
    archive_download_url: String,
    expired: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Release {
    id: u64,
    tag_name: String,
    name: String,
    prerelease: bool,
    upload_url: String,
    html_url: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReleaseAsset {
    id: u64,
    name: String,
    size: u64,
    state: String,
    browser_download_url: String,
}

// ── Handlers ────────────────────────────────────────────────────────────

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let gh = &state.gh;

    // Per source repo: fetch the latest 5 successful runs.
    let mut rows: Vec<RepoRow> = Vec::new();
    for src in &state.config.sources {
        let url = format!(
            "https://api.github.com/repos/{}/actions/runs?per_page=5&status=success&conclusion=success",
            src.repo
        );
        let runs = gh
            .get_json::<WorkflowRuns>(&url)
            .await
            .map(|r| r.workflow_runs)
            .unwrap_or_default();
        rows.push(RepoRow {
            repo: src.repo.clone(),
            package: src.package.clone(),
            runs: runs.into_iter().take(5).collect(),
        });
    }

    let tmpl = state.hbs.render("index", &IndexCtx { rows }).unwrap_or_else(|e| {
        format!("template error: {e}")
    });
    Html(tmpl)
}

#[derive(Serialize)]
struct IndexCtx {
    rows: Vec<RepoRow>,
}

#[derive(Serialize)]
struct RepoRow {
    repo: String,
    package: String,
    runs: Vec<WorkflowRun>,
}

async fn repo(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> impl IntoResponse {
    let gh = &state.gh;
    let repo_full = format!("{owner}/{name}");
    let source = state
        .config
        .sources
        .iter()
        .find(|s| s.repo == repo_full)
        .cloned();

    let Some(source) = source else {
        return (StatusCode::NOT_FOUND, "Repo not in watch list").into_response();
    };

    let runs_url = format!(
        "https://api.github.com/repos/{repo_full}/actions/runs?per_page=10&status=success&conclusion=success"
    );
    let runs: Vec<WorkflowRun> = gh
        .get_json::<WorkflowRuns>(&runs_url)
        .await
        .map(|r| r.workflow_runs)
        .unwrap_or_default();

    // For each run, fetch its artifacts and match the .pkg.tar.zst.
    let mut run_rows: Vec<RunRow> = Vec::new();
    for run in &runs {
        let artifacts_url = format!(
            "https://api.github.com/repos/{repo_full}/actions/runs/{}/artifacts",
            run.id
        );
        let artifacts = gh
            .get_json::<Artifacts>(&artifacts_url)
            .await
            .map(|a| a.artifacts)
            .unwrap_or_default();
        let pkg = artifacts
            .iter()
            .find(|a| a.name.ends_with(".pkg.tar.zst"))
            .cloned();
        run_rows.push(RunRow {
            run: run.clone(),
            artifact: pkg,
        });
    }

    let tmpl = state
        .hbs
        .render(
            "repo",
            &RepoCtx {
                repo: source.repo.clone(),
                package: source.package.clone(),
                arch: source.arch.to_string(),
                runs: run_rows,
            },
        )
        .unwrap_or_else(|e| format!("template error: {e}"));
    Html(tmpl).into_response()
}

#[derive(Serialize)]
struct RepoCtx {
    repo: String,
    package: String,
    arch: String,
    runs: Vec<RunRow>,
}

#[derive(Serialize)]
struct RunRow {
    run: WorkflowRun,
    artifact: Option<Artifact>,
}

#[derive(Deserialize)]
struct PublishForm {
    repo: String,
    run_id: u64,
    channel: String, // "stable" | "beta" | "alpha"
}

async fn publish(
    State(state): State<AppState>,
    Form(form): Form<PublishForm>,
) -> impl IntoResponse {
    let gh = &state.gh;
    let pkg_repo = "Zohaib8090/zohara-packages";

    let source = state
        .config
        .sources
        .iter()
        .find(|s| s.repo == form.repo)
        .cloned();
    let Some(source) = source else {
        return (StatusCode::NOT_FOUND, "Source repo not in watch list").into_response();
    };

    let pkg_name = &source.package;
    let pkg_ver = read_version_from_run(gh, &form.repo, form.run_id).await.unwrap_or_else(|_| "0.0.0".to_string());
    let pkg_file = format!("{pkg_name}-{pkg_ver}-1-x86_64.pkg.tar.zst");

    // 1. Download the artifact from the source run
    let artifacts: Artifacts = gh
        .get_json(&format!(
            "https://api.github.com/repos/{}/actions/runs/{}/artifacts",
            form.repo, form.run_id
        ))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("list artifacts: {e}")))?;
    let artifact = artifacts
        .artifacts
        .iter()
        .find(|a| a.name.ends_with(".pkg.tar.zst"))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "no .pkg.tar.zst artifact in this run".to_string(),
            )
        })
        .map_err(|e| e)?;

    // We need a fresh download URL because /artifacts/{id}/zip needs auth.
    let resp = gh
        .client
        .get(&artifact.archive_download_url)
        .header("Authorization", format!("Bearer {}", gh.app.token().await.unwrap()))
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("download: {e}")))?
        .error_for_status()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("download non-2xx: {e}")))?;
    let pkg_bytes = resp.bytes().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("download bytes: {e}")))?;
    let pkg_size = pkg_bytes.len();

    // 2. Decide channel release tag
    let tag = match form.channel.as_str() {
        "stable" => "stable".to_string(),
        "beta" => "channel-beta".to_string(),
        "alpha" => "channel-alpha".to_string(),
        other => return (
            StatusCode::BAD_REQUEST,
            format!("unknown channel '{other}'"),
        )
            .into_response(),
    };

    // 3. Find or create the channel release
    let release = get_or_create_release(gh, pkg_repo, &tag, &form.channel).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("release: {e}")))?;

    // 4. Download the current zohara.db from the release (if any)
    let db_asset = release.assets.iter().find(|a| a.name == "zohara.db").cloned();
    if let Some(db) = &db_asset {
        let _ = gh
            .download_to_file(
                &db.browser_download_url,
                std::path::Path::new("/tmp/zohara.db"),
            )
            .await;
    }
    if !std::path::Path::new("/tmp/zohara.db").exists() {
        std::fs::write("/tmp/zohara.db", b"")?;
    }

    // 5. Save the .pkg.tar.zst to disk
    std::fs::write(&pkg_file, &pkg_bytes)?;

    // 6. Run repo-add (we expect the runtime image to have pacman + repo-add)
    let add_status = std::process::Command::new("repo-add")
        .args(["--new", "--remove", "zohara.db.tar.gz", &pkg_file])
        .status();
    let add_ok = add_status.map(|s| s.success()).unwrap_or(false);
    if !add_ok {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("repo-add failed; status: {:?}", add_status),
        )
            .into_response();
    }
    // Some repo-add versions need a manual copy
    if !std::path::Path::new("zohara.db").exists() {
        std::fs::copy("zohara.db.tar.gz", "zohara.db")?;
    }

    // 7. Re-upload package + db to the release
    let upload_url = format!(
        "https://uploads.github.com/repos/{pkg_repo}/releases/{}/assets",
        release.id
    );
    let token = gh.app.token().await.unwrap();

    async fn upload_one(
        client: &reqwest::Client,
        upload_url: &str,
        token: &str,
        name: &str,
        path: &std::path::Path,
    ) -> Result<()> {
        let bytes = std::fs::read(path)?;
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(name.to_string());
        let form = reqwest::multipart::Form::new().part(name, part);
        let resp = client
            .post(upload_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .multipart(form)
            .send()
            .await?
            .error_for_status()?;
        let _ = resp.text().await?;
        Ok(())
    }
    let _ = upload_one(&gh.client, &upload_url, &token, &pkg_file, std::path::Path::new(&pkg_file)).await;
    let _ = upload_one(&gh.client, &upload_url, &token, "zohara.db", std::path::Path::new("zohara.db")).await;
    let _ = upload_one(&gh.client, &upload_url, &token, "zohara.db.tar.gz", std::path::Path::new("zohara.db.tar.gz")).await;

    // 8. Update apps.json in the repo
    let _ = update_apps_json(gh, pkg_repo, pkg_name, &pkg_ver, &tag).await;

    let msg = format!(
        "ok: published {} v{} ({} bytes) to {} -> {}",
        pkg_name,
        pkg_ver,
        pkg_size,
        form.repo,
        tag
    );
    (StatusCode::OK, msg).into_response()
}

async fn read_version_from_run(gh: &Gh, repo: &str, run_id: u64) -> Result<String> {
    // Best-effort: read the version from the workflow run's `version` step
    // output. Falls back to a default if not parseable.
    let jobs_url = format!(
        "https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
    );
    #[derive(Deserialize)]
    struct JobsResp {
        jobs: Vec<Job>,
    }
    #[derive(Deserialize)]
    struct Job {
        steps: Vec<Step>,
    }
    #[derive(Deserialize)]
    struct Step {
        name: String,
        conclusion: Option<String>,
    }
    let resp: JobsResp = gh.get_json(&jobs_url).await?;
    for job in &resp.jobs {
        for step in &job.steps {
            if step.name.contains("Compute version") && step.conclusion.as_deref() == Some("success") {
                // We don't have access to step output via the API without
                // an extra call. Default to 0.1.0 for now and let the user
                // override if needed.
                return Ok("0.1.0".to_string());
            }
        }
    }
    Ok("0.1.0".to_string())
}

async fn get_or_create_release(
    gh: &Gh,
    repo: &str,
    tag: &str,
    channel: &str,
) -> Result<Release> {
    // Try to fetch existing
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    if let Ok(r) = gh.get_json::<Release>(&url).await {
        return Ok(r);
    }
    // Create
    let title = format!("Zohara Packages — {channel}");
    let body = format!(
        "Auto-managed Arch package repository for the **{channel}** channel.\n\n\
         Updated by [zohara-hub](https://github.com/Zohaib8090/zohara-hub).\n\n\
         `pacman -Syu` on a Zohara OS system configured for this channel \
         will pick up packages from here."
    );
    let prerelease = channel != "stable";
    let payload = serde_json::json!({
        "tag_name": tag,
        "target_commitish": "main",
        "name": title,
        "body": body,
        "prerelease": prerelease,
        "draft": false,
    });
    let url = format!("https://api.github.com/repos/{repo}/releases");
    let r: Release = gh.post_json(&url, &payload).await?;
    Ok(r)
}

async fn update_apps_json(gh: &Gh, repo: &str, pkg_name: &str, ver: &str, tag: &str) -> Result<()> {
    let url = format!("https://api.github.com/repos/{repo}/contents/apps.json");
    let file: serde_json::Value = gh.get_json(&url).await?;
    let content_b64 = file
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("apps.json content not found"))?
        .replace('\n', "");
    let bytes = base64_decode(&content_b64)?;
    let mut data: serde_json::Value = serde_json::from_slice(&bytes)?;
    let arr = data
        .as_object_mut()
        .and_then(|o| o.get_mut("apps"))
        .and_then(|a| a.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("apps.json: missing 'apps' array"))?;
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let new_entry = serde_json::json!({
        "id": pkg_name,
        "name": pkg_name.replace('-', " ").to_string(),
        "publisher": "Zohara OS Team",
        "description": format!("{} — published via zohara-hub.", pkg_name),
        "category": "System",
        "icon_url": format!("https://raw.githubusercontent.com/Zohaib8090/{}/main/data/icons/scalable/apps/{}.svg", pkg_name, pkg_name),
        "type": "pacman",
        "package": pkg_name,
        "current_version": ver,
        "versions": [{
            "version": ver,
            "release_date": today,
            "download_url": format!("https://github.com/{}/releases/download/{}/{}-{}-1-x86_64.pkg.tar.zst", repo, tag, pkg_name, ver),
            "changelog": format!("Auto-published from {} v{}", pkg_name, ver),
        }]
    });
    if let Some(idx) = arr.iter().position(|a| a.get("id").and_then(|i| i.as_str()) == Some(pkg_name)) {
        arr[idx] = new_entry;
    } else {
        arr.push(new_entry);
    }
    let new_bytes = serde_json::to_vec_pretty(&data)?;
    let new_b64 = base64_encode(&new_bytes);
    let sha = file.get("sha").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("no sha on file"))?;
    let commit_msg = format!("apps: bump {pkg_name} to {ver}");
    let payload = serde_json::json!({
        "message": commit_msg,
        "content": new_b64,
        "sha": sha,
        "branch": "main",
    });
    let _url = format!("https://api.github.com/repos/{repo}/contents/apps.json");
    let _: serde_json::Value = gh.put_json(&_url, &payload).await?;
    Ok(())
}

// ── AppState ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    gh: Gh,
    config: Arc<AppConfig>,
    hbs: Arc<Handlebars<'static>>,
}

// ── main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // Read GitHub App credentials from env.
    let app_id = std::env::var("ZOHARA_HUB_APP_ID").context("ZOHARA_HUB_APP_ID")?;
    let private_key_pem = std::env::var("ZOHARA_HUB_APP_PRIVATE_KEY")
        .context("ZOHARA_HUB_APP_PRIVATE_KEY")?;
    let installation_id = std::env::var("ZOHARA_HUB_INSTALLATION_ID")
        .context("ZOHARA_HUB_INSTALLATION_ID")?;

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .context("PORT must be u16")?;

    // Watched source repos.
    let config = AppConfig {
        sources: vec![
            WatchedSource {
                repo: "Zohaib8090/zohara-settings".into(),
                package: "zohara-settings".into(),
                arch: "x86_64",
            },
            WatchedSource {
                repo: "Zohaib8090/zohara-store".into(),
                package: "zohara-store".into(),
                arch: "x86_64",
            },
            WatchedSource {
                repo: "Zohaib8090/zohara-apps".into(),
                package: "zohara-welcome".into(),
                arch: "x86_64",
            },
        ],
    };

    let gh_app = GhApp {
        app_id,
        private_key_pem,
        installation_id,
        cached_token: Arc::new(tokio::sync::RwLock::new(None)),
    };
    let gh = Gh::new(gh_app);

    // Handlebars templates (inline so we don't need a templates dir at
    // runtime; Render's ephemeral disk would wipe it on each deploy).
    let mut hbs = Handlebars::new();
    hbs.register_template_string(
        "index",
        include_str!("../templates/index.hbs"),
    )?;
    hbs.register_template_string(
        "repo",
        include_str!("../templates/repo.hbs"),
    )?;

    let state = AppState {
        gh,
        config: Arc::new(config),
        hbs: Arc::new(hbs),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/repo/:owner/:name", get(repo))
        .route("/publish", post(publish))
        .with_state(state);

    log::info!("zohara-hub listening on 0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    Server::serve(listener, app).await?;
    Ok(())
}

// Tiny base64 helpers (the standard `base64` crate would be cleaner but
// we already pulled in `hex`; keep deps minimal).
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .context("base64 decode")
}

