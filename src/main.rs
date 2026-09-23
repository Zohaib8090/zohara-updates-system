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
    extract::{Form, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc, time::Duration};
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

// ── Auth ─────────────────────────────────────────────────────────────────
//
// There was no auth at all before this: POST /publish downloads a build
// artifact and pushes it straight into the OTA release + apps.json with
// no check on who called it, only what a link to this service's port is.
// HTTP Basic protects every route (the dashboard has nothing that needs to
// stay public) -- it needs no new dependency (base64 is already pulled in
// for the GitHub asset-upload path) and every browser handles the login
// prompt itself, so the templates don't need a login page.
fn check_basic_auth(headers: &HeaderMap, user: &str, pass: &str) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(b64) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    text == format!("{user}:{pass}")
}

async fn require_auth(
    State(s): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    if check_basic_auth(&headers, &s.auth_user, &s.auth_pass) {
        return next.run(request).await;
    }
    let mut resp = (StatusCode::UNAUTHORIZED, "authentication required\n").into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"zohara-updates-system\"".parse().unwrap(),
    );
    resp
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

    /// Like `get_bytes` but uses the vnd.github+json Accept header.
    /// Required for artifact zip downloads — the redirected S3 endpoint
    /// rejects `Accept: application/octet-stream` with 415.
    async fn get_bytes_json_accept(&self, url: &str) -> Result<Vec<u8>> {
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

    // Distinct from put_json: GitHub's "create a release" is POST
    // /repos/{owner}/{repo}/releases, not PUT. put_json is kept for the
    // one call that genuinely is a PUT (Contents API create-or-update, used
    // by update_apps_json) -- using it for release creation too was silently
    // wrong: a PUT to the releases *collection* URL 404s/405s rather than
    // creating anything, so ensure_release() could never actually create a
    // channel's first release.
    async fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let auth = self.auth_header().await?;
        let resp = self
            .client
            .post(url)
            .header("Authorization", auth)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "zohara-updates-system")
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url} non-2xx"))?;
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
        // The upload URL from GitHub looks like:
        //   https://uploads.github.com/.../releases/.../assets{?name,label}
        // It's a URI template -- strip the {?name,label} suffix and
        // append our own ?name=... .
        let base = release_upload_url
            .split('{')
            .next()
            .unwrap_or(release_upload_url);
        let url = format!("{base}?name={}", urlencode(name));
        let auth = self.auth_header().await?;

        // Step 1: POST to api.github.com / uploads.github.com with the
        // raw file body. GitHub returns 302 with a Location header
        // pointing to S3 (pre-signed). We do NOT follow the redirect;
        // reqwest strips the body on 302 and that breaks S3.
        let no_redirect = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build no-redirect client")?;
        let resp = no_redirect
            .post(&url)
            .header("Authorization", auth)
            .header("Accept", "*/*")
            .header("User-Agent", "zohara-updates-system")
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        // 200/201 = direct success (some old releases don't redirect)
        if status.is_success() {
            return Ok(());
        }
        // 302 = GitHub returned the S3 URL
        if status != reqwest::StatusCode::FOUND && status != reqwest::StatusCode::TEMPORARY_REDIRECT {
            let t = resp.text().await.unwrap_or_default();
            bail!("upload asset `{name}` step 1: HTTP {status} body={t}");
        }
        let s3_url = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("no Location header on 302"))?
            .to_string();

        // Step 2: PUT the body to S3. No auth needed (URL is pre-signed).
        // No Accept: application/vnd.github+json header either, just like
        // GitHub's docs say for S3 upload.
        let s3_resp = no_redirect
            .put(&s3_url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .with_context(|| format!("PUT {s3_url}"))?;
        let s3_status = s3_resp.status();
        if !s3_status.is_success() {
            let t = s3_resp.text().await.unwrap_or_default();
            bail!("upload asset `{name}` step 2: HTTP {s3_status} body={t}");
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
    auth_user: String,
    auth_pass: String,
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
    let zip_bytes = match s.gh.get_bytes_json_accept(&art.archive_download_url).await {
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

    // 4. List everything already on the release: every previously
    // published .pkg.tar.zst AND whatever db asset (under whatever name)
    // is there. repo-add only knows about the package files sitting next
    // to the db when it runs -- it does not consult the db's own file
    // list to go fetch anything -- so an earlier version of this handler,
    // which downloaded nothing but the db before calling repo-add, wiped
    // every other package from the channel on every single publish.
    let assets: Vec<ReleaseAsset> = match s.gh.get_json(&format!(
        "https://api.github.com/repos/{}/{}/releases/{}/assets",
        pkg_repo.0, pkg_repo.1, release.id
    )).await {
        Ok(x) => x,
        Err(e) => return err_page(&format!("list release assets: {e:#}")),
    };
    let db_assets: Vec<&ReleaseAsset> = assets
        .iter()
        .filter(|a| a.name == "zohara.db" || a.name.starts_with("zohara.db."))
        .collect();
    let other_pkgs: Vec<&ReleaseAsset> = assets
        .iter()
        .filter(|a| a.name.ends_with(".pkg.tar.zst") && a.name != pkg_name)
        .collect();
    for a in &other_pkgs {
        // a.url (the assets API endpoint), not browser_download_url: it
        // needs the same auth header as everything else here, and works
        // the same whether or not zohara-packages is ever made private.
        let bytes = match s.gh.get_bytes(&a.url).await {
            Ok(b) => b,
            Err(e) => return err_page(&format!("download existing package {}: {e:#}", a.name)),
        };
        if let Err(e) = std::fs::write(work.join(&a.name), bytes) {
            return err_page(&format!("write existing package {}: {e}", a.name));
        }
    }
    // The new package too, alongside the others, so repo-add sees the
    // whole channel in one directory.
    if let Err(e) = std::fs::copy(&pkg_path, work.join(&pkg_name)) {
        return err_page(&format!("stage new package: {e}"));
    }

    // 5. Rebuild zohara.db.tar.gz from every *.pkg.tar.zst now in work/.
    // Not zohara.db.tar.zst: pacman.conf's [zohara] section fetches
    // "<Server>/zohara.db" (no compression suffix, and gzip is what a
    // bare "zohara.db" copy needs to actually be), and a mismatched name
    // just means the file sits on the release unused while pacman 404s.
    let pkg_globs: Vec<_> = match std::fs::read_dir(&work) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".pkg.tar.zst")))
            .collect(),
        Err(e) => return err_page(&format!("read work dir: {e}")),
    };
    let out = match std::process::Command::new("repo-add")
        .current_dir(&work)
        .arg("zohara.db.tar.gz")
        .args(&pkg_globs)
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
    let new_db = match std::fs::read(work.join("zohara.db.tar.gz")) {
        Ok(b) => b,
        Err(e) => return err_page(&format!("read new zohara.db: {e}")),
    };

    // 6. Delete every old db asset (under any name -- clears out a stale
    // zohara.db.tar.zst from before this fix too) and the old copy of the
    // package being replaced, so the re-upload below isn't left sitting
    // next to a stale duplicate under a slightly different name.
    for a in &db_assets {
        if let Err(e) = s.gh.delete_asset_by_id(&pkg_repo.0, &pkg_repo.1, a.id).await {
            return err_page(&format!("delete old db asset {}: {e:#}", a.name));
        }
    }
    if let Some(a) = assets.iter().find(|a| a.name == pkg_name) {
        if let Err(e) = s.gh.delete_asset_by_id(&pkg_repo.0, &pkg_repo.1, a.id).await {
            return err_page(&format!("delete old pkg: {e:#}"));
        }
    }

    // 7. Upload the rebuilt db (both names pacman might look for) and the
    // new package.
    let pkg_upload_bytes = match std::fs::read(&pkg_path) {
        Ok(b) => b,
        Err(e) => return err_page(&format!("read pkg for upload: {e}")),
    };
    if let Err(e) = s.gh.upload_asset(&release.upload_url, "zohara.db.tar.gz", &new_db).await {
        return err_page(&format!("upload zohara.db.tar.gz: {e:#}"));
    }
    if let Err(e) = s.gh.upload_asset(&release.upload_url, "zohara.db", &new_db).await {
        return err_page(&format!("upload zohara.db: {e:#}"));
    }
    if let Err(e) = s.gh.upload_asset(&release.upload_url, &pkg_name, &pkg_upload_bytes).await {
        return err_page(&format!("upload pkg: {e:#}"));
    }

    // 8. Update apps.json in the package repo
    if let Err(e) = update_apps_json(&s.gh, &pkg_repo.0, &pkg_repo.1, &pkg_name, &tag).await {
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
        .post_json(&url, &new)
        .await
        .context("create release")?;
    Ok(r)
}

/// "zohara-settings-0.1.0-1-x86_64.pkg.tar.zst" -> ("zohara-settings", "0.1.0").
/// Arch package names may themselves contain dashes, so this trims known
/// fixed suffixes from the right instead of splitting on the first dash.
fn parse_pkg_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename
        .strip_suffix(".pkg.tar.zst")
        .or_else(|| filename.strip_suffix(".pkg.tar.xz"))?;
    let stem = stem.strip_suffix("-x86_64").or_else(|| stem.strip_suffix("-any"))?;
    let (rest, _pkgrel) = stem.rsplit_once('-')?;
    let (pkgname, pkgver) = rest.rsplit_once('-')?;
    Some((pkgname.to_string(), pkgver.to_string()))
}

/// Patches the *real* apps.json schema ({"apps": [...], "featured": [...],
/// ...}), matching what zohara-packages/.github/workflows/publish.yml
/// writes. The previous version of this function ignored that schema
/// entirely and treated the whole file as a flat {package: metadata} map,
/// which meant every publish through this dashboard added a stray
/// top-level key (e.g. "zohara-settings-0.1.0-1-x86_64") next to the real
/// "apps" array instead of updating an app's entry in it -- confirmed
/// still sitting in apps.json from the 2026-09-07 publish through here.
async fn update_apps_json(gh: &Gh, owner: &str, name: &str, pkg_filename: &str, tag: &str) -> Result<()> {
    let Some((pkg, ver)) = parse_pkg_filename(pkg_filename) else {
        bail!("could not parse package name/version out of '{pkg_filename}'");
    };
    let url = format!("https://api.github.com/repos/{owner}/{name}/contents/apps.json");
    let existing: ContentEntry = gh.get_json(&url).await.context("fetch apps.json metadata")?;
    let dl = existing
        .download_url
        .as_ref()
        .ok_or_else(|| anyhow!("apps.json has no download_url"))?;
    let bytes = gh.get_bytes(dl).await.context("download apps.json")?;
    let mut data: serde_json::Value =
        serde_json::from_slice(&bytes).context("apps.json is not valid JSON")?;

    let apps = data
        .get_mut("apps")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| anyhow!("apps.json has no \"apps\" array"))?;
    let today = chrono::Utc::now().date_naive().to_string();
    let download_url =
        format!("https://github.com/{owner}/{name}/releases/download/{tag}/{pkg_filename}");
    let new_version = serde_json::json!({
        "version": ver,
        "release_date": today,
        "download_url": download_url,
        "changelog": format!("Published from {pkg} v{ver} via zohara-updates-system"),
    });

    match apps.iter_mut().find(|a| a.get("id").and_then(|v| v.as_str()) == Some(pkg.as_str())
        || a.get("package").and_then(|v| v.as_str()) == Some(pkg.as_str()))
    {
        Some(entry) => {
            entry["current_version"] = serde_json::Value::String(ver.clone());
            let versions = entry["versions"].as_array_mut().ok_or_else(|| anyhow!("entry has no versions array"))?;
            match versions.iter_mut().find(|v| v.get("version").and_then(|v| v.as_str()) == Some(ver.as_str())) {
                Some(v) => *v = new_version,
                None => {
                    versions.insert(0, new_version);
                    versions.truncate(10);
                }
            }
        }
        None => {
            apps.push(serde_json::json!({
                "id": pkg,
                "name": pkg.replace('-', " "),
                "publisher": "Zohara OS Team",
                "description": format!("{pkg} — published via zohara-updates-system."),
                "category": "System",
                "icon_url": format!(
                    "https://raw.githubusercontent.com/{owner}/{pkg}/main/data/icons/scalable/apps/{pkg}.svg"
                ),
                "type": "pacman",
                "package": pkg,
                "current_version": ver,
                "versions": [new_version],
            }));
        }
    }

    let body = serde_json::to_string_pretty(&data)?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());

    #[derive(Serialize)]
    struct PutFile<'a> {
        message: &'a str,
        content: &'a str,
        sha: &'a str,
    }
    let put = PutFile {
        message: &format!("chore(publish): record {pkg} {ver} via zohara-updates-system"),
        content: &b64,
        sha: &existing.sha,
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
    // Required, not defaulted: this dashboard can push packages into the
    // OTA channel real users' machines pull from, so there is no safe
    // fallback credential to ship if the operator forgets to set one.
    let auth_user = require_env("ZOHARA_HUB_ADMIN_USER")?;
    let auth_pass = require_env("ZOHARA_HUB_ADMIN_PASS")?;
    let state = AppState {
        cfg: Arc::new(cfg),
        gh,
        auth_user,
        auth_pass,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/repo/:owner/:name", get(repo_view))
        .route("/publish", post(publish))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        // /health stays outside auth: hosting platforms (Render) poll it
        // without credentials to decide whether to keep the service up.
        .route("/health", get(health))
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
