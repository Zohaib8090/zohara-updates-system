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
// Endpoints (everything except /health, /login and /auth/callback needs the signed-in owner, see auth.rs):
//   GET  /                          list watched repos + recent runs
//   GET  /repo/{owner}/{name}       single-repo view + publish buttons
//   POST /publish                   do the publish (download -> repo-add -> upload); off until phase 2
//   GET  /login, /auth/callback     sign in with GitHub (only ZOHARA_HUB_ALLOWED_USER_ID gets in)
//   POST /logout
//
// State: none. All authoritative state is GitHub; the session is a signed cookie.
// See docs/PLAN.md for where this is going.

mod auth;

use anyhow::{anyhow, bail, Context, Result};
use askama::Template;
use axum::{
    extract::{Form, Path, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Router,
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
    // Login (see auth.rs)
    client_id: String,
    client_secret: String,
    session_secret: Vec<u8>,
    allowed_user_id: u64,
    base_url: String, // public address, e.g. https://zohara-updates-system.onrender.com (no trailing slash)
    // Publishing stays off until phase 2 (the publish code below still replaces the whole package database).
    publish_enabled: bool,
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
        let session_secret = require_env("ZOHARA_HUB_SESSION_SECRET")?.into_bytes();
        if session_secret.len() < 32 {
            bail!("ZOHARA_HUB_SESSION_SECRET must be at least 32 characters");
        }
        Ok(Self {
            app_id,
            installation_id,
            private_key_pem,
            watched_repos: watched,
            pkg_repo,
            client_id: require_env("ZOHARA_HUB_CLIENT_ID")?,
            client_secret: require_env("ZOHARA_HUB_CLIENT_SECRET")?,
            session_secret,
            allowed_user_id: require_env("ZOHARA_HUB_ALLOWED_USER_ID")?
                .parse()
                .context("ZOHARA_HUB_ALLOWED_USER_ID is not a number")?,
            base_url: require_env("ZOHARA_HUB_BASE_URL")?.trim_end_matches('/').to_string(),
            publish_enabled: env::var("ZOHARA_HUB_PUBLISH_ENABLED").map(|v| v == "1").unwrap_or(false),
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
    #[serde(default)]
    head_repository: Option<RunRepo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RunRepo {
    full_name: String,
}

/// A run may be published only if it is a finished, successful build of the watched repo itself, from its `main`
/// branch, started by a push or by hand. This refuses pull-request runs (a fork can run a workflow too), runs on
/// other branches and runs of any other repository.
fn run_is_publishable(run: &WorkflowRun, repo_full: &str) -> Result<(), String> {
    if run.status != "completed" || run.conclusion.as_deref() != Some("success") {
        return Err("that run did not finish successfully".into());
    }
    if run.head_branch != "main" {
        return Err(format!("that run is from branch `{}`, only `main` can be published", run.head_branch));
    }
    if run.event != "push" && run.event != "workflow_dispatch" {
        return Err(format!("that run was started by `{}`, only push or manual runs can be published", run.event));
    }
    match &run.head_repository {
        Some(r) if r.full_name.eq_ignore_ascii_case(repo_full) => Ok(()),
        _ => Err("that run does not come from the watched repository itself".into()),
    }
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
    csrf: &'a str,
}

#[derive(Template)]
#[template(path = "repo.html")]
struct RepoTpl<'a> {
    title: &'a str,
    repo: &'a RepoSummary,
    runs: &'a [WorkflowRun],
    csrf: &'a str,
    publish_enabled: bool,
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
    csrf: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
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

async fn index(State(s): State<AppState>, Extension(sess): Extension<auth::Session>) -> Response {
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
        csrf: &sess.csrf,
    })
}

async fn repo_view(
    State(s): State<AppState>,
    Extension(sess): Extension<auth::Session>,
    Path((owner, name)): Path<(String, String)>,
) -> Response {
    let full = format!("{owner}/{name}");
    if !is_watched(&s.cfg, &owner, &name) {
        return (StatusCode::NOT_FOUND, "not a watched repository\n").into_response();
    }
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
        csrf: &sess.csrf,
        publish_enabled: s.cfg.publish_enabled,
    })
}

fn is_watched(cfg: &AppConfig, owner: &str, name: &str) -> bool {
    cfg.watched_repos
        .iter()
        .any(|(o, n)| o.eq_ignore_ascii_case(owner) && n.eq_ignore_ascii_case(name))
}

async fn publish(
    State(s): State<AppState>,
    Extension(sess): Extension<auth::Session>,
    Form(f): Form<PublishForm>,
) -> Response {
    if !auth::same(&f.csrf, &sess.csrf) {
        return (StatusCode::FORBIDDEN, "bad or missing CSRF token\n").into_response();
    }
    if !s.cfg.publish_enabled {
        return err_page("Publishing is switched off until phase 2 of docs/PLAN.md is done.");
    }
    let (owner, name) = match f.repo.split_once('/') {
        Some((o, n)) => (o.to_owned(), n.to_owned()),
        None => return err_page("repo must be owner/name"),
    };
    // Only the watched repositories, never whatever the form says.
    if !is_watched(&s.cfg, &owner, &name) {
        return (StatusCode::FORBIDDEN, "not a watched repository\n").into_response();
    }
    let run_url = format!("https://api.github.com/repos/{owner}/{name}/actions/runs/{}", f.run_id);
    let run: WorkflowRun = match s.gh.get_json(&run_url).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("look up run {}: {e:#}", f.run_id)),
    };
    if let Err(why) = run_is_publishable(&run, &format!("{owner}/{name}")) {
        return err_page(&why);
    }
    do_publish(s, f).await
}

// ── Login ───────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn cookie_from(req: &Request, name: &str) -> Option<String> {
    let h = req.headers().get(header::COOKIE)?.to_str().ok()?;
    auth::cookie_value(h, name).map(|v| v.to_string())
}

fn with_cookies(mut resp: Response, cookies: &[String]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// Everything behind this needs the signed-in owner. Browsers get sent to /login, anything else gets 401.
async fn require_login(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let session = cookie_from(&req, auth::SESSION_COOKIE)
        .and_then(|v| auth::read_session(&s.cfg.session_secret, &v, now_unix(), s.cfg.allowed_user_id));
    match session {
        Some(sess) => {
            req.extensions_mut().insert(sess);
            let mut resp = next.run(req).await;
            resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        None => {
            if req.method() == axum::http::Method::GET {
                Redirect::to("/login").into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "sign in first\n").into_response()
            }
        }
    }
}

async fn login(State(s): State<AppState>) -> Response {
    let state = auth::random_token();
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
        urlencode(&s.cfg.client_id),
        urlencode(&format!("{}/auth/callback", s.cfg.base_url)),
        urlencode(&state),
    );
    let sealed = auth::seal(&s.cfg.session_secret, &state);
    with_cookies(
        Redirect::to(&url).into_response(),
        &[auth::set_cookie(auth::STATE_COOKIE, &sealed, auth::STATE_SECONDS)],
    )
}

async fn auth_callback(State(s): State<AppState>, Query(q): Query<CallbackQuery>, req: Request) -> Response {
    let denied = |msg: &str| {
        with_cookies(
            (StatusCode::FORBIDDEN, format!("{msg}\n")).into_response(),
            &[auth::clear_cookie(auth::STATE_COOKIE)],
        )
    };
    if q.error.is_some() {
        return denied("GitHub sign-in was cancelled");
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return denied("missing code or state");
    };
    // The `state` must be the one this browser was given at /login.
    let expected = cookie_from(&req, auth::STATE_COOKIE).and_then(|v| auth::open(&s.cfg.session_secret, &v));
    if !expected.map(|e| auth::same(&e, &state)).unwrap_or(false) {
        return denied("sign-in state does not match, start again at /login");
    }
    let user_id = match github_user_id(&s.cfg, &code).await {
        Ok(id) => id,
        Err(e) => {
            log::warn!("sign-in failed: {e:#}");
            return denied("could not complete the GitHub sign-in");
        }
    };
    if user_id != s.cfg.allowed_user_id {
        log::warn!("sign-in refused for GitHub user id {user_id}");
        return denied("this GitHub account is not allowed here");
    }
    let (cookie, _csrf) = auth::make_session_cookie_value(&s.cfg.session_secret, user_id, now_unix());
    with_cookies(
        Redirect::to("/").into_response(),
        &[
            auth::set_cookie(auth::SESSION_COOKIE, &cookie, auth::SESSION_SECONDS),
            auth::clear_cookie(auth::STATE_COOKIE),
        ],
    )
}

/// Trades the one-time `code` for a user token, then asks GitHub who that is. The token is dropped right away.
async fn github_user_id(cfg: &AppConfig, code: &str) -> Result<u64> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?;
    let tok: serde_json::Value = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "zohara-updates-system")
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", &format!("{}/auth/callback", cfg.base_url)),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let access = tok
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no access_token in GitHub's answer"))?;
    let user: serde_json::Value = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "zohara-updates-system")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    user.get("id").and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("no id in GitHub's /user answer"))
}

async fn logout(Extension(sess): Extension<auth::Session>, Form(f): Form<CsrfForm>) -> Response {
    if !auth::same(&f.csrf, &sess.csrf) {
        return (StatusCode::FORBIDDEN, "bad or missing CSRF token\n").into_response();
    }
    with_cookies(Redirect::to("/login").into_response(), &[auth::clear_cookie(auth::SESSION_COOKIE)])
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

    // 4. Find existing zohara.db asset (if any) and replace it
    let assets: Vec<ReleaseAsset> = match s.gh.get_json(&format!(
        "https://api.github.com/repos/{}/{}/releases/{}/assets",
        pkg_repo.0, pkg_repo.1, release.id
    )).await {
        Ok(x) => x,
        Err(e) => return err_page(&format!("list release assets: {e:#}")),
    };
    // Match the db by its base name, regardless of compression
    // extension (zohara.db, zohara.db.tar.gz, zohara.db.tar.zst, ...).
    let db_asset = assets
        .iter()
        .find(|a| a.name == "zohara.db" || a.name.starts_with("zohara.db."))
        .cloned();
    let pkg_asset = assets.iter().find(|a| a.name == pkg_name).cloned();
    // 4b. Also delete any leftover .pkg.tar.zst files for the same package
    // version (rare, but happens if the same version was previously published
    // under a slightly different name).

    // 5. Run repo-add to add the package to the local db
    let out = match std::process::Command::new("repo-add")
        .current_dir(&work)
        .arg("zohara.db.tar.zst")
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
    let new_db = match std::fs::read(work.join("zohara.db.tar.zst")) {
        Ok(b) => b,
        Err(e) => return err_page(&format!("read new zohara.db: {e}")),
    };

    // 6. Delete old assets (so we can re-upload with same name)
    if let Some(a) = &db_asset {
        if let Err(e) = s.gh.delete_asset_by_id(&pkg_repo.0, &pkg_repo.1, a.id).await {
            return err_page(&format!("delete old db asset: {e:#}"));
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
    let pkg_upload_bytes = match std::fs::read(&pkg_path) {
        Ok(b) => b,
        Err(e) => return err_page(&format!("read pkg for upload: {e}")),
    };
    if let Err(e) = s.gh.upload_asset(&release.upload_url, "zohara.db.tar.zst", &new_db).await {
        return err_page(&format!("upload zohara.db.tar.zst: {e:#}"));
    }
    if let Err(e) = s.gh.upload_asset(&release.upload_url, &pkg_name, &pkg_upload_bytes).await {
        return err_page(&format!("upload pkg: {e:#}"));
    }

    // 8. Update apps.json in the package repo
    if let Err(e) = update_apps_json(&s.gh, &pkg_repo.0, &pkg_repo.1, &pkg_name).await {
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

// ── Health ───────────────────────────────────────────────────

async fn health() -> &'static str {
    "ok\n"
}


// ── Keep-awake ──────────────────────────────────────────────────────────

/// Render's free web services go to sleep after 15 minutes without incoming requests. Calling our own public
/// address (not localhost: the request has to come in through Render's front door to count) every 10 minutes
/// keeps this one awake while it is running. It cannot wake a service that is already asleep or suspended, and it
/// uses free instance hours (about 730 a month for one always-on service, the free allowance is 750).
/// Switch off with ZOHARA_HUB_SELF_PING=0.
fn spawn_self_ping(base_url: String) {
    if env::var("ZOHARA_HUB_SELF_PING").map(|v| v == "0").unwrap_or(false) {
        log::info!("self-ping is off");
        return;
    }
    let url = format!("{base_url}/health");
    tokio::spawn(async move {
        let client = match reqwest::Client::builder().timeout(Duration::from_secs(20)).build() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("self-ping disabled: {e}");
                return;
            }
        };
        // Let the server finish starting before the first call.
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            match client.get(&url).header("User-Agent", "zohara-updates-system self-ping").send().await {
                Ok(r) if r.status().is_success() => log::debug!("self-ping ok"),
                Ok(r) => log::warn!("self-ping got HTTP {}", r.status()),
                Err(e) => log::warn!("self-ping failed: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
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
    let base_url_for_ping = cfg.base_url.clone();
    let state = AppState {
        cfg: Arc::new(cfg),
        gh,
    };

    // Anything added to `protected` is behind the login; only the three routes in `open` are public.
    let protected = Router::new()
        .route("/", get(index))
        .route("/repo/:owner/:name", get(repo_view))
        .route("/publish", post(publish))
        .route("/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_login));
    let open = Router::new()
        .route("/health", get(health))
        .route("/login", get(login))
        .route("/auth/callback", get(auth_callback));
    let app = Router::new().merge(protected).merge(open).with_state(state);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("bind 0.0.0.0:{port}"))?;
    log::info!("zohara-updates-system listening on 0.0.0.0:{port}");
    spawn_self_ping(base_url_for_ping);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(branch: &str, event: &str, status: &str, conclusion: Option<&str>, repo: Option<&str>) -> WorkflowRun {
        WorkflowRun {
            id: 1,
            name: "Build".into(),
            head_branch: branch.into(),
            head_sha: "0123456789abcdef".into(),
            display_title: "t".into(),
            status: status.into(),
            conclusion: conclusion.map(Into::into),
            event: event.into(),
            created_at: "x".into(),
            updated_at: "x".into(),
            html_url: "x".into(),
            head_repository: repo.map(|r| RunRepo { full_name: r.into() }),
        }
    }

    const REPO: &str = "Zohaib8090/zohara-settings";

    #[test]
    fn good_run_is_publishable() {
        assert!(run_is_publishable(&run("main", "push", "completed", Some("success"), Some(REPO)), REPO).is_ok());
        assert!(run_is_publishable(&run("main", "workflow_dispatch", "completed", Some("success"), Some("zohaib8090/ZOHARA-settings")), REPO).is_ok());
    }

    #[test]
    fn bad_runs_are_refused() {
        let bad = [
            run("feature", "push", "completed", Some("success"), Some(REPO)),
            run("main", "pull_request", "completed", Some("success"), Some(REPO)),
            run("main", "push", "completed", Some("failure"), Some(REPO)),
            run("main", "push", "in_progress", None, Some(REPO)),
            run("main", "push", "completed", Some("success"), Some("attacker/zohara-settings")),
            run("main", "push", "completed", Some("success"), None),
        ];
        for r in bad {
            assert!(run_is_publishable(&r, REPO).is_err(), "{r:?}");
        }
    }

    #[test]
    fn urlencode_escapes() {
        assert_eq!(urlencode("a b&c"), "a%20b%26c");
    }
}
