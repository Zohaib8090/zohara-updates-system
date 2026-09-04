// Zohara Updates System — tiny web dashboard that watches our
// package-building repos (zohara-settings, zohara-store, zohara-apps)
// and lets you re-publish their latest successful build artifact to
// the OTA channel release in Zohaib8090/zohara-packages.
//
// Stack: Rust 1.88, axum 0.7, reqwest 0.12 (rustls), askama 0.12,
// jsonwebtoken 9, base64 0.22, serde, tokio, log.
//
// Auth: GitHub App. The app is installed on the watched repos with
// contents:read and on zohara-packages with contents:write. We mint a
// short-lived JWT, exchange it for an installation token, and use
// that to call the GitHub REST API.
//
// Endpoints:
//   GET  /                          list watched repos + recent runs
//   GET  /repo/{owner}/{name}       single-repo view + publish buttons
//   POST /publish                   do the publish (download -> repo-add -> upload)
//
// State: none. All authoritative state is GitHub.

use anyhow::{anyhow, bail, Context, Result};
use askama::Template;
use axum::{
    extract::{Form, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, sync::Arc, time::Duration};
use tokio::sync::RwLock;

// ── App config from env vars ────────────────────────────────────────────

#[derive(Clone, Debug)]
struct AppConfig {
    app_id: u64,
    installation_id: u64,
    private_key_pem: String,
    watched_repos: Vec<(String, String)>, // (owner, name)
    pkg_repo: (String, String),           // (owner, name)
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let app_id: u64 = require_env("ZOHARA_HUB_APP_ID")?
            .parse()
            .context("ZOHARA_HUB_APP_ID is not a number")?;
        let installation_id: u64 = require_env("ZOHARA_HUB_INSTALLATION_ID")?
            .parse()
            .context("ZOHARA_HUB_INSTALLATION_ID is not a number")?;
        let private_key_pem =
            require_env("ZOHARA_HUB_APP_PRIVATE_KEY")?.replace("\\n", "\n");
        let owner = env::var("ZOHARA_HUB_OWNER").unwrap_or_else(|_| "Zohaib8090".into());
        let watched = vec![
            (owner.clone(), "zohara-settings".into()),
            (owner.clone(), "zohara-apps".into()),
        ];
        let pkg_repo = (
            env::var("ZOHARA_HUB_PKG_OWNER").unwrap_or_else(|_| owner.clone()),
            env::var("ZOHARA_HUB_PKG_REPO")
                .unwrap_or_else(|_| "zohara-packages".into()),
        );
        Ok(Self {
            app_id,
            installation_id,
            private_key_pem,
            watched_repos: watched,
            pkg_repo,
        })
    }
}

fn require_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} not set"))
}

// ── GitHub App auth ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct GithubAppClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Clone)]
struct AppAuth {
    app_id: u64,
    installation_id: u64,
    pem: String,
    client: reqwest::Client,
    cache: Arc<RwLock<Option<(String, std::time::Instant)>>>,
}

impl AppAuth {
    fn new(app_id: u64, installation_id: u64, pem: String) -> Self {
        Self {
            app_id,
            installation_id,
            pem,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            cache: Arc::new(RwLock::new(None)),
        }
    }

    fn mint_jwt(&self) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let claims = GithubAppClaims {
            iat: now - 60,
            exp: now + 9 * 60,
            iss: self.app_id.to_string(),
        };
        let key = EncodingKey::from_rsa_pem(self.pem.as_bytes())
            .context("invalid ZOHARA_HUB_APP_PRIVATE_KEY")?;
        let header = Header::new(Algorithm::RS256);
        Ok(encode(&header, &claims, &key)?)
    }

    async fn token(&self) -> Result<String> {
        {
            let r = self.cache.read().await;
            if let Some((tok, when)) = r.as_ref() {
                if when.elapsed() < Duration::from_secs(50 * 60) {
                    return Ok(tok.clone());
                }
            }
        }
        let jwt = self.mint_jwt()?;
        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            self.installation_id
        );
        let resp: serde_json::Value = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-updates-system")
            .send()
            .await
            .context("POST installations/access_tokens")?
            .error_for_status()
            .context("installations/access_tokens non-2xx")?
            .json()
            .await?;
        let token = resp
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("no `token` in installation response"))?
            .to_string();
        *self.cache.write().await = Some((token.clone(), std::time::Instant::now()));
        Ok(token)
    }
}

// ── GitHub REST helpers ─────────────────────────────────────────────────

#[derive(Clone)]
struct Gh {
    auth: AppAuth,
    client: reqwest::Client,
}

impl Gh {
    fn new(auth: AppAuth) -> Self {
        Self {
            auth,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap(),
        }
    }

    async fn auth_header(&self) -> Result<String> {
        Ok(format!("Bearer {}", self.auth.token().await?))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let auth = self.auth_header().await?;
        let resp = self
            .client
            .get(url)
            .header("Authorization", auth)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-updates-system")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} non-2xx"))?;
        Ok(resp.json().await?)
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let auth = self.auth_header().await?;
        let resp = self
            .client
            .get(url)
            .header("Authorization", auth)
            .header("Accept", "application/octet-stream")
            .header("User-Agent", "zohara-updates-system")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} non-2xx"))?;
        Ok(resp.bytes().await?.to_vec())
    }

    async fn put_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let auth = self.auth_header().await?;
        let resp = self
            .client
            .put(url)
            .header("Authorization", auth)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-updates-system")
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?
            .error_for_status()
            .with_context(|| format!("PUT {url} non-2xx"))?;
        Ok(resp.json().await?)
    }

    async fn delete(&self, url: &str) -> Result<()> {
        let auth = self.auth_header().await?;
        self.client
            .delete(url)
            .header("Authorization", auth)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-updates-system")
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?
            .error_for_status()
            .with_context(|| format!("DELETE {url} non-2xx"))?;
        Ok(())
    }

    async fn upload_asset(
        &self,
        release_upload_url: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let base = release_upload_url.split('?').next().unwrap_or(release_upload_url);
        let url = format!("{base}?name={}", urlencode(name));
        let auth = self.auth_header().await?;
        let resp = self
            .client
            .post(&url)
            .header("Authorization", auth)
            .header("Accept", "application/vnd.github+json")
            .header("Content-Type", "application/octet-stream")
            .header("User-Agent", "zohara-updates-system")
            .body(bytes.to_vec())
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let s = resp.status();
        if s.as_u16() == 422 {
            bail!("asset `{name}` already exists on this release (HTTP 422)");
        }
        if !s.is_success() {
            let t = resp.text().await.unwrap_or_default();
            bail!("upload asset `{name}`: HTTP {s} {t}");
        }
        Ok(())
    }

    async fn delete_asset_by_id(&self, owner: &str, name: &str, asset_id: u64) -> Result<()> {
        self.delete(&format!(
            "https://api.github.com/repos/{owner}/{name}/releases/assets/{asset_id}"
        ))
        .await
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

// ── Domain types ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WorkflowRuns {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WorkflowRun {
    id: u64,
    #[serde(default)]
    name: String,
    head_branch: String,
    head_sha: String,
    display_title: String,
    status: String,
    conclusion: Option<String>,
    #[serde(default)]
    event: String,
    created_at: String,
    updated_at: String,
    html_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Artifacts {
    artifacts: Vec<Artifact>,
    total_count: u64,
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
    upload_url: String,
    html_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RepoInfo {
    full_name: String,
    description: Option<String>,
    stargazers_count: u64,
    open_issues_count: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ReleaseAsset {
    id: u64,
    name: String,
    url: String,
    browser_download_url: String,
    size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ContentEntry {
    name: String,
    path: String,
    sha: String,
    download_url: Option<String>,
}

// ── HTML templates (askama) ─────────────────────────────────────────────

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTpl<'a> {
    title: &'a str,
    repos: &'a [RepoSummary],
    err: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "repo.html")]
struct RepoTpl<'a> {
    title: &'a str,
    repo: &'a RepoSummary,
    runs: &'a [WorkflowRun],
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTpl<'a> {
    title: &'a str,
    err: &'a str,
}

#[derive(Clone, Serialize)]
struct RepoSummary {
    owner: String,
    name: String,
    full: String,
    description: String,
    stars: u64,
    issues: u64,
    html_url: String,
}

// ── App state ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    cfg: Arc<AppConfig>,
    gh: Gh,
}

#[derive(Deserialize)]
struct PublishForm {
    repo: String,
    run_id: u64,
    channel: String,
}

// ── Handlers ────────────────────────────────────────────────────────────

fn err_page(msg: &str) -> Response {
    let html = ErrorTpl {
        title: "zohara-updates-system",
        err: msg,
    }
    .render()
    .unwrap_or_else(|e| format!("template err: {e}\norig: {msg}"));
    (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
}

fn render_html<T: Template>(t: T) -> Response {
    match t.render() {
        Ok(b) => Html(b).into_response(),
        Err(e) => err_page(&format!("template error: {e}")),
    }
}

async fn index(State(s): State<AppState>) -> Response {
    let mut summaries = Vec::new();
    for (owner, name) in &s.cfg.watched_repos {
        let url = format!("https://api.github.com/repos/{owner}/{name}");
        match s.gh.get_json::<RepoInfo>(&url).await {
            Ok(r) => summaries.push(RepoSummary {
                owner: owner.clone(),
                name: name.clone(),
                full: r.full_name,
                description: r.description.unwrap_or_default(),
                stars: r.stargazers_count,
                issues: r.open_issues_count,
                html_url: format!("https://github.com/{owner}/{name}"),
            }),
            Err(e) => {
                log::warn!("skip {owner}/{name}: {e}");
            }
        }
    }
    render_html(IndexTpl {
        title: "zohara-updates-system",
        repos: &summaries,
        err: None,
    })
}

async fn repo_view(
    State(s): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Response {
    let full = format!("{owner}/{name}");
    let repo_url = format!("https://api.github.com/repos/{full}");
    let runs_url = format!(
        "https://api.github.com/repos/{full}/actions/runs?per_page=15&status=success"
    );

    let repo: RepoInfo = match s.gh.get_json(&repo_url).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("failed to load {full}: {e}")),
    };
    let runs: WorkflowRuns = match s.gh.get_json(&runs_url).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("failed to list runs for {full}: {e}")),
    };

    let summary = RepoSummary {
        owner: owner.clone(),
        name: name.clone(),
        full: repo.full_name,
        description: repo.description.unwrap_or_default(),
        stars: repo.stargazers_count,
        issues: repo.open_issues_count,
        html_url: format!("https://github.com/{full}"),
    };
    render_html(RepoTpl {
        title: "zohara-updates-system",
        repo: &summary,
        runs: &runs.workflow_runs,
    })
}

async fn publish(
    State(s): State<AppState>,
    Form(f): Form<PublishForm>,
) -> Response {
    do_publish(s, f).await
}

async fn do_publish(s: AppState, f: PublishForm) -> Response {
    let (owner, name) = match f.repo.split_once('/') {
        Some(p) => p.to_owned(),
        None => return err_page("repo must be owner/name"),
    };
    let channel = f.channel.to_lowercase();
    if !["stable", "beta", "alpha"].contains(&channel.as_str()) {
        return err_page(&format!("invalid channel: {channel}"));
    }
    let pkg_repo = (s.cfg.pkg_repo.0.clone(), s.cfg.pkg_repo.1.clone());

    // 1. List the run's artifacts. We accept ANY artifact (not just one
    //    named *.pkg.tar.zst) because some workflows upload a generic
    //    name like "zohara-settings-arch-x86_64" containing the package
    //    inside as a zip.
    let arts_url = format!(
        "https://api.github.com/repos/{owner}/{name}/actions/runs/{}/artifacts",
        f.run_id
    );
    let arts: Artifacts = match s.gh.get_json(&arts_url).await {
        Ok(x) => x,
        Err(e) => return err_page(&format!("list artifacts: {e:#}")),
    };
    let art = match arts.artifacts.into_iter().next() {
        Some(x) => x,
        None => return err_page("no artifacts on this run"),
    };

    // 2. Download the artifact (it's a zip wrapping the .pkg.tar.zst)
    let zip_bytes = match s.gh.get_bytes(&art.archive_download_url).await {
        Ok(x) => x,
        Err(e) => return err_page(&format!("download artifact: {e:#}")),
    };
    let work = env::temp_dir().join(format!("zohara-pub-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    if let Err(e) = std::fs::create_dir_all(&work) {
        return err_page(&format!("mkdir work: {e}"));
    }
    let zip_path = work.join("artifact.zip");
    if let Err(e) = std::fs::write(&zip_path, &zip_bytes) {
        return err_page(&format!("write zip: {e}"));
    }

    // 3. Unzip and locate the .pkg.tar.zst inside
    let extract = work.join("extract");
    std::fs::create_dir_all(&extract).ok();
    let zip_status = std::process::Command::new("unzip")
        .arg("-o")
        .arg(&zip_path)
        .arg("-d")
        .arg(&extract)
        .output();
    let zip_ok = match zip_status {
        Ok(o) if o.status.success() => true,
        _ => false,
    };
    if !zip_ok {
        return err_page("artifact is not a zip (no `unzip` or invalid format)");
    }
    let pkg_path = match std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("find {} -type f -name '*.pkg.tar.zst' | head -1", extract.display()))
        .output()
    {
        Ok(o) if o.status.success() => {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if p.is_empty() {
                return err_page("no .pkg.tar.zst found inside artifact zip");
            }
            std::path::PathBuf::from(p)
        }
        _ => return err_page("find .pkg.tar.zst failed"),
    };
    let pkg_name = pkg_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("package.pkg.tar.zst")
        .to_string();

    // 3. Get/create the channel release
    let tag = if channel == "stable" {
        "stable".to_string()
    } else {
        format!("channel-{channel}")
    };
    let release = match ensure_release(&s.gh, &pkg_repo.0, &pkg_repo.1, &tag, &channel).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("ensure release: {e:#}")),
    };

    // 4. Find existing zohara.db asset (if any) and replace it
    let assets: Vec<ReleaseAsset> = match s.gh.get_json(&format!(
        "https://api.github.com/repos/{}/{}/releases/{}/assets",
        pkg_repo.0, pkg_repo.1, release.id
    )).await {
        Ok(x) => x,
        Err(e) => return err_page(&format!("list release assets: {e:#}")),
    };
    let db_asset = assets.iter().find(|a| a.name == "zohara.db").cloned();
    let pkg_asset = assets.iter().find(|a| a.name == art.name).cloned();

    // 5. Run repo-add to add the package to the local db
    let out = match std::process::Command::new("repo-add")
        .current_dir(&work)
        .arg("zohara.db")
        .arg(&pkg_path)
        .output() {
        Ok(o) => o,
        Err(e) => return err_page(&format!("repo-add: {e}")),
    };
    if !out.status.success() {
        return err_page(&format!(
            "repo-add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let new_db = match std::fs::read(work.join("zohara.db")) {
        Ok(b) => b,
        Err(e) => return err_page(&format!("read new zohara.db: {e}")),
    };

    // 6. Delete old assets (so we can re-upload with same name)
    if let Some(a) = &db_asset {
        if let Err(e) = s.gh.delete_asset_by_id(&pkg_repo.0, &pkg_repo.1, a.id).await {
            return err_page(&format!("delete old zohara.db: {e:#}"));
        }
    }
    if let Some(a) = &pkg_asset {
        if pkg_asset.as_ref().map(|x| x.id) != db_asset.as_ref().map(|x| x.id) {
            if let Err(e) = s.gh.delete_asset_by_id(&pkg_repo.0, &pkg_repo.1, a.id).await {
                return err_page(&format!("delete old pkg: {e:#}"));
            }
        }
    }

    // 7. Upload the new db and the new package
    if let Err(e) = s.gh.upload_asset(&release.upload_url, "zohara.db", &new_db).await {
        return err_page(&format!("upload zohara.db: {e:#}"));
    }
    if let Err(e) = s.gh.upload_asset(&release.upload_url, &art.name, &pkg_bytes).await {
        return err_page(&format!("upload pkg: {e:#}"));
    }

    // 8. Update apps.json in the package repo
    if let Err(e) = update_apps_json(&s.gh, &pkg_repo.0, &pkg_repo.1, &art.name).await {
        log::warn!("apps.json update skipped: {e:#}");
    }

    Redirect::to(&format!("/repo/{owner}/{name}")).into_response()
}

async fn ensure_release(
    gh: &Gh,
    owner: &str,
    name: &str,
    tag: &str,
    channel: &str,
) -> Result<Release> {
    let by_tag = format!("https://api.github.com/repos/{owner}/{name}/releases/tags/{tag}");
    if let Ok(r) = gh.get_json::<Release>(&by_tag).await {
        return Ok(r);
    }
    #[derive(Serialize)]
    struct NewRelease<'a> {
        tag_name: &'a str,
        name: &'a str,
        body: &'a str,
        draft: bool,
        prerelease: bool,
    }
    let new = NewRelease {
        tag_name: tag,
        name: &format!("Zohara {channel} channel"),
        body: &format!("Auto-managed by zohara-updates-system. OTA channel: {channel}."),
        draft: false,
        prerelease: channel != "stable",
    };
    let url = format!("https://api.github.com/repos/{owner}/{name}/releases");
    let r: Release = gh
        .put_json(&url, &new)
        .await
        .context("create release")?;
    Ok(r)
}

async fn update_apps_json(
    gh: &Gh,
    owner: &str,
    name: &str,
    pkg_filename: &str,
) -> Result<()> {
    let pkg = pkg_filename.trim_end_matches(".pkg.tar.zst");
    let url = format!("https://api.github.com/repos/{owner}/{name}/contents/apps.json");
    let existing: Option<ContentEntry> = gh.get_json(&url).await.ok();
    let mut apps: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    if let Some(e) = &existing {
        if let Some(dl) = &e.download_url {
            if let Ok(bytes) = gh.get_bytes(dl).await {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if let Some(obj) = v.as_object() {
                        for (k, v) in obj {
                            apps.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }
    }
    apps.insert(
        pkg.to_string(),
        serde_json::json!({
            "last_published": chrono::Utc::now().to_rfc3339(),
            "source": "zohara-updates-system",
            "filename": pkg_filename,
        }),
    );
    let body = serde_json::to_string_pretty(&apps)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());

    #[derive(Serialize)]
    struct PutFile<'a> {
        message: &'a str,
        content: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha: Option<&'a str>,
    }
    let put = PutFile {
        message: &format!("chore(publish): record {pkg} via zohara-updates-system"),
        content: &b64,
        sha: existing.as_ref().map(|e| e.sha.as_str()),
    };
    let _: serde_json::Value = gh.put_json(&url, &put).await?;
    Ok(())
}

// ── Health / fallback ───────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok\n"
}

async fn root_fallback() -> Redirect {
    Redirect::to("/")
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    let cfg = AppConfig::from_env()?;
    let auth = AppAuth::new(
        cfg.app_id,
        cfg.installation_id,
        cfg.private_key_pem.clone(),
    );
    let gh = Gh::new(auth);
    let state = AppState {
        cfg: Arc::new(cfg),
        gh,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/repo/:owner/:name", get(repo_view))
        .route("/publish", post(publish))
        .with_state(state);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("bind 0.0.0.0:{port}"))?;
    log::info!("zohara-updates-system listening on 0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}
