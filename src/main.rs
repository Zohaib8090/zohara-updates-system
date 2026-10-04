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
    iso_repo: (String, String),           // the repo whose CI builds the ISO (owner, name)
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
        let iso_repo = (owner.clone(), "zohara".to_string());
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
            iso_repo,
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

    /// POST a JSON body; returns the HTTP status and the body text (GitHub answers 204 with no body on success).
    async fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<(reqwest::StatusCode, String)> {
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
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        Ok((status, resp.text().await.unwrap_or_default()))
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
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RepoInfo {
    full_name: String,
    description: Option<String>,
    stargazers_count: u64,
    open_issues_count: u64,
}

// ── HTML templates (askama) ─────────────────────────────────────────────

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTpl<'a> {
    active: &'a str,
    repos: &'a [RepoSummary],
    live_iso: Option<LiveIso>,
    err: Option<&'a str>,
    csrf: &'a str,
}

#[derive(Template)]
#[template(path = "repo.html")]
struct RepoTpl<'a> {
    active: &'a str,
    repo: &'a RepoSummary,
    runs: &'a [WorkflowRun],
    csrf: &'a str,
    publish_enabled: bool,
    notice: Option<&'a str>,
    actions_url: &'a str,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTpl<'a> {
    active: &'a str,
    csrf: &'a str,
    err: &'a str,
}

#[derive(Template)]
#[template(path = "iso.html")]
struct IsoTpl<'a> {
    active: &'a str,
    csrf: &'a str,
    builds: &'a [IsoBuild],
    live_iso: Option<LiveIso>,
    publish_enabled: bool,
    notice: Option<&'a str>,
    err: Option<&'a str>,
    actions_url: &'a str,
}

/// One finished ISO build that can be promoted.
struct IsoBuild {
    id: u64,
    title: String,
    sha7: String,
    created_at: String,
    html_url: String,
    size_gb: String,
    expires: String,
}

/// What `latest.json` in the public bucket says is published now (written by the Promote ISO workflow).
#[derive(Deserialize, Clone, Debug)]
struct LiveIso {
    version: String,
    file: String,
    sha256: String,
    size: u64,
    url: String,
    #[serde(skip)]
    size_gb: String,
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
struct RepoQuery {
    notice: Option<String>,
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
        active: "",
        csrf: "",
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
        active: "packages",
        repos: &summaries,
        live_iso: fetch_live_iso(&s).await,
        err: None,
        csrf: &sess.csrf,
    })
}

async fn repo_view(
    State(s): State<AppState>,
    Extension(sess): Extension<auth::Session>,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<RepoQuery>,
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
        active: "packages",
        repo: &summary,
        runs: &runs.workflow_runs,
        csrf: &sess.csrf,
        publish_enabled: s.cfg.publish_enabled,
        // Only known keys become text; nothing from the URL is shown as it is.
        notice: match q.notice.as_deref() {
            Some("started") => Some("Publish started. It takes a minute or two; follow it on the Actions page below."),
            _ => None,
        },
        actions_url: &format!(
            "https://github.com/{}/{}/actions/workflows/publish.yml",
            s.cfg.pkg_repo.0, s.cfg.pkg_repo.1
        ),
    })
}

// ── ISO promotion ───────────────────────────────────────────────────────

/// Name of the CI workflow in the ISO repo, and of the artifact that holds the ISO. `promote-iso.yml` in
/// zohara-packages checks the same things again before it copies anything.
const ISO_WORKFLOW_NAME: &str = "Build Zohara OS ISO";
const ISO_ARTIFACT: &str = "zohara-os-x86_64";
/// Public bucket the ISO is promoted to (the workflow writes `latest.json` there last).
const ISO_PUBLIC_BASE: &str = "https://objectstorage.ap-mumbai-1.oraclecloud.com/n/bm27e3oxmp04/b/zohara-os/o/";

/// A finished, successful ISO build from the ISO repo's `master`, started by a push or by hand.
fn iso_run_is_publishable(run: &WorkflowRun, repo_full: &str) -> Result<(), String> {
    if run.status != "completed" || run.conclusion.as_deref() != Some("success") {
        return Err("that run did not finish successfully".into());
    }
    if run.name != ISO_WORKFLOW_NAME {
        return Err(format!("that run is `{}`, not `{ISO_WORKFLOW_NAME}`", run.name));
    }
    if run.head_branch != "master" {
        return Err(format!("that run is from branch `{}`, only `master` can be promoted", run.head_branch));
    }
    if !["push", "workflow_dispatch", "repository_dispatch"].contains(&run.event.as_str()) {
        return Err(format!("that run was started by `{}`, which is not accepted", run.event));
    }
    match &run.head_repository {
        Some(r) if r.full_name.eq_ignore_ascii_case(repo_full) => Ok(()),
        _ => Err("that run does not come from the ISO repository itself".into()),
    }
}

fn gigabytes(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
}

/// The `repository_dispatch` body that starts zohara-packages' Promote ISO workflow.
fn iso_dispatch_body(run_id: u64) -> serde_json::Value {
    serde_json::json!({
        "event_type": "iso-promote",
        "client_payload": { "run_id": run_id.to_string(), "requested_via": "zohara-updates-system" },
    })
}

/// Reads `latest.json` from the public bucket. `None` when there is none yet or it cannot be read; this never
/// stops a page from showing.
async fn fetch_live_iso(s: &AppState) -> Option<LiveIso> {
    let resp = s.gh.client.get(format!("{ISO_PUBLIC_BASE}latest.json")).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut l: LiveIso = resp.json().await.ok()?;
    l.size_gb = gigabytes(l.size);
    Some(l)
}

async fn iso_view(
    State(s): State<AppState>,
    Extension(sess): Extension<auth::Session>,
    Query(q): Query<RepoQuery>,
) -> Response {
    let (owner, name) = s.cfg.iso_repo.clone();
    let full = format!("{owner}/{name}");
    let runs_url = format!("https://api.github.com/repos/{full}/actions/runs?branch=master&status=success&per_page=30");
    let runs: WorkflowRuns = match s.gh.get_json(&runs_url).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("failed to list ISO builds of {full}: {e:#}")),
    };
    let mut builds = Vec::new();
    for run in runs.workflow_runs.iter().filter(|r| iso_run_is_publishable(r, &full).is_ok()).take(6) {
        let arts_url = format!("https://api.github.com/repos/{full}/actions/runs/{}/artifacts", run.id);
        let Ok(arts) = s.gh.get_json::<Artifacts>(&arts_url).await else { continue };
        // Builds whose file GitHub already deleted cannot be promoted, so they are not listed.
        let Some(a) = arts.artifacts.iter().find(|a| a.name == ISO_ARTIFACT && !a.expired) else { continue };
        builds.push(IsoBuild {
            id: run.id,
            title: run.display_title.clone(),
            sha7: run.head_sha.chars().take(7).collect(),
            created_at: run.created_at.clone(),
            html_url: run.html_url.clone(),
            size_gb: gigabytes(a.size_in_bytes),
            expires: a.expires_at.clone().unwrap_or_default().chars().take(10).collect(),
        });
    }
    render_html(IsoTpl {
        active: "iso",
        csrf: &sess.csrf,
        builds: &builds,
        live_iso: fetch_live_iso(&s).await,
        publish_enabled: s.cfg.publish_enabled,
        notice: match q.notice.as_deref() {
            Some("started") => Some("Promote started. Copying a 4 GB file takes 10 to 20 minutes; follow it on the Actions page."),
            _ => None,
        },
        err: None,
        actions_url: &format!(
            "https://github.com/{}/{}/actions/workflows/promote-iso.yml",
            s.cfg.pkg_repo.0, s.cfg.pkg_repo.1
        ),
    })
}

#[derive(Deserialize)]
struct PromoteIsoForm {
    run_id: u64,
    csrf: String,
}

async fn publish_iso(
    State(s): State<AppState>,
    Extension(sess): Extension<auth::Session>,
    Form(f): Form<PromoteIsoForm>,
) -> Response {
    if !auth::same(&f.csrf, &sess.csrf) {
        return (StatusCode::FORBIDDEN, "bad or missing CSRF token\n").into_response();
    }
    if !s.cfg.publish_enabled {
        return err_page("Publishing is switched off (ZOHARA_HUB_PUBLISH_ENABLED is not 1).");
    }
    let (owner, name) = s.cfg.iso_repo.clone();
    let full = format!("{owner}/{name}");
    let run: WorkflowRun = match s.gh.get_json(&format!("https://api.github.com/repos/{full}/actions/runs/{}", f.run_id)).await {
        Ok(r) => r,
        Err(e) => return err_page(&format!("look up run {}: {e:#}", f.run_id)),
    };
    if let Err(why) = iso_run_is_publishable(&run, &full) {
        return err_page(&why);
    }
    let arts: Artifacts = match s.gh.get_json(&format!("https://api.github.com/repos/{full}/actions/runs/{}/artifacts", f.run_id)).await {
        Ok(a) => a,
        Err(e) => return err_page(&format!("list artifacts of run {}: {e:#}", f.run_id)),
    };
    if !arts.artifacts.iter().any(|a| a.name == ISO_ARTIFACT && !a.expired) {
        return err_page("this build's ISO file is gone from GitHub (it keeps them 30 days)");
    }
    let url = format!("https://api.github.com/repos/{}/{}/dispatches", s.cfg.pkg_repo.0, s.cfg.pkg_repo.1);
    match s.gh.post_json(&url, &iso_dispatch_body(f.run_id)).await {
        Ok((st, _)) if st == StatusCode::NO_CONTENT => {
            log::info!("iso promote started: run {}", f.run_id);
            Redirect::to("/iso?notice=started").into_response()
        }
        Ok((st, text)) => err_page(&format!("GitHub refused to start the promote: HTTP {st} {text}")),
        Err(e) => err_page(&format!("could not reach GitHub: {e:#}")),
    }
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
        return err_page("Publishing is switched off (ZOHARA_HUB_PUBLISH_ENABLED is not 1).");
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
    let channel = f.channel.to_lowercase();
    if !["stable", "beta", "alpha"].contains(&channel.as_str()) {
        return err_page(&format!("invalid channel: {channel}"));
    }
    // The run must still have an artifact to publish (GitHub deletes them after a while).
    let arts_url = format!("https://api.github.com/repos/{owner}/{name}/actions/runs/{}/artifacts", f.run_id);
    let arts: Artifacts = match s.gh.get_json(&arts_url).await {
        Ok(a) => a,
        Err(e) => return err_page(&format!("list artifacts of run {}: {e:#}", f.run_id)),
    };
    let live: Vec<&Artifact> = arts.artifacts.iter().filter(|a| !a.expired).collect();
    if live.is_empty() {
        return err_page("this run has no downloadable artifacts left (GitHub deletes them after a while)");
    }
    let artifact_name = if live.len() == 1 { Some(live[0].name.as_str()) } else { None };
    // The publishing itself runs in GitHub Actions (zohara-packages/.github/workflows/publish.yml), which checks
    // everything again. This site only chooses the run and the channel and starts it.
    let body = dispatch_body(&format!("{owner}/{name}"), f.run_id, &channel, artifact_name);
    let url = format!("https://api.github.com/repos/{}/{}/dispatches", s.cfg.pkg_repo.0, s.cfg.pkg_repo.1);
    match s.gh.post_json(&url, &body).await {
        Ok((st, _)) if st == StatusCode::NO_CONTENT => {
            log::info!("publish started: {owner}/{name} run {} -> {channel}", f.run_id);
            Redirect::to(&format!("/repo/{owner}/{name}?notice=started")).into_response()
        }
        Ok((st, text)) => err_page(&format!("GitHub refused to start the publish: HTTP {st} {text}")),
        Err(e) => err_page(&format!("could not reach GitHub: {e:#}")),
    }
}

/// The `repository_dispatch` body that starts zohara-packages' publish workflow.
fn dispatch_body(source_repo: &str, run_id: u64, channel: &str, artifact_name: Option<&str>) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "run_id": run_id.to_string(),
        "source_repo": source_repo,
        "channel": channel,
        "requested_via": "zohara-updates-system",
    });
    if let Some(a) = artifact_name {
        payload["artifact_name"] = a.into();
    }
    serde_json::json!({ "event_type": "package-published", "client_payload": payload })
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
        .route("/iso", get(iso_view))
        .route("/publish-iso", post(publish_iso))
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
    const ISO_REPO: &str = "Zohaib8090/zohara";

    fn iso_run(branch: &str, event: &str, conclusion: Option<&str>, name: &str, repo: Option<&str>) -> WorkflowRun {
        let mut r = run(branch, event, "completed", conclusion, repo);
        r.name = name.into();
        r
    }

    #[test]
    fn good_iso_run_is_promotable() {
        for ev in ["push", "workflow_dispatch", "repository_dispatch"] {
            assert!(iso_run_is_publishable(&iso_run("master", ev, Some("success"), ISO_WORKFLOW_NAME, Some(ISO_REPO)), ISO_REPO).is_ok());
        }
    }

    #[test]
    fn bad_iso_runs_are_refused() {
        let ok = |b, e, c, n, r| iso_run_is_publishable(&iso_run(b, e, c, n, r), ISO_REPO).is_ok();
        assert!(!ok("master", "push", Some("failure"), ISO_WORKFLOW_NAME, Some(ISO_REPO)));
        assert!(!ok("main", "push", Some("success"), ISO_WORKFLOW_NAME, Some(ISO_REPO)));
        assert!(!ok("master", "pull_request", Some("success"), ISO_WORKFLOW_NAME, Some(ISO_REPO)));
        assert!(!ok("master", "push", Some("success"), "Some other workflow", Some(ISO_REPO)));
        assert!(!ok("master", "push", Some("success"), ISO_WORKFLOW_NAME, Some("Evil/zohara")));
        assert!(!ok("master", "push", Some("success"), ISO_WORKFLOW_NAME, None));
    }

    #[test]
    fn iso_dispatch_body_shape() {
        let b = iso_dispatch_body(42);
        assert_eq!(b["event_type"], "iso-promote");
        assert_eq!(b["client_payload"]["run_id"], "42");
    }

    #[test]
    fn gigabytes_formats() {
        assert_eq!(gigabytes(3_920_658_608), "3.9 GB");
    }

    #[test]
    fn latest_json_parses() {
        let l: LiveIso = serde_json::from_str(r#"{"version":"2026.10.05","file":"a.iso","sha256":"ab","size":5,"url":"https://x/a.iso"}"#).unwrap();
        assert_eq!(l.file, "a.iso");
    }

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

    #[test]
    fn dispatch_body_shape() {
        let b = dispatch_body("Zohaib8090/zohara-apps", 35880065846, "alpha", Some("zohara-apps-x86_64"));
        assert_eq!(b["event_type"], "package-published");
        assert_eq!(b["client_payload"]["run_id"], "35880065846");
        assert_eq!(b["client_payload"]["source_repo"], "Zohaib8090/zohara-apps");
        assert_eq!(b["client_payload"]["channel"], "alpha");
        assert_eq!(b["client_payload"]["artifact_name"], "zohara-apps-x86_64");
        let b = dispatch_body("Zohaib8090/zohara-settings", 1, "stable", None);
        assert!(b["client_payload"].get("artifact_name").is_none());
    }

    /// Renders every page with sample data. Set ZHUB_RENDER_DIR to also write the HTML files and look at them.
    #[test]
    fn pages_render() {
        let repo = RepoSummary {
            owner: "Zohaib8090".into(), name: "zohara-settings".into(), full: "Zohaib8090/zohara-settings".into(),
            description: "Settings app".into(), stars: 0, issues: 0, html_url: "https://github.com/Zohaib8090/zohara-settings".into(),
        };
        let live = LiveIso { version: "2026.09.30".into(), file: "zohara-os-2026.09.30-x86_64.iso".into(), sha256: "ab12".into(), size: 3_900_000_000, url: "https://x/a.iso".into(), size_gb: "3.9 GB".into() };
        let r = run("main", "push", "completed", Some("success"), Some(REPO));
        let build = IsoBuild { id: 7, title: "Dockerfile: cache brave".into(), sha7: "abcdef0".into(), created_at: "2026-09-30T08:58:26Z".into(), html_url: "https://x".into(), size_gb: "3.9 GB".into(), expires: "2026-10-30".into() };
        let pages = [
            ("index", IndexTpl { active: "packages", repos: &[repo.clone()], live_iso: Some(live.clone()), err: None, csrf: "tok" }.render().unwrap()),
            ("repo", RepoTpl { active: "packages", repo: &repo, runs: &[r], csrf: "tok", publish_enabled: true, notice: Some("Publish started."), actions_url: "https://x" }.render().unwrap()),
            ("iso", IsoTpl { active: "iso", csrf: "tok", builds: &[build], live_iso: Some(live), publish_enabled: true, notice: None, err: None, actions_url: "https://x" }.render().unwrap()),
            ("error", ErrorTpl { active: "", csrf: "", err: "boom" }.render().unwrap()),
        ];
        assert!(pages[2].1.contains("/publish-iso") && pages[2].1.contains("Promote ISO"));
        assert!(!pages[3].1.contains("Sign out"));
        if let Ok(dir) = std::env::var("ZHUB_RENDER_DIR") {
            for (n, h) in &pages { std::fs::write(format!("{dir}/{n}.html"), h).unwrap(); }
        }
    }
}
