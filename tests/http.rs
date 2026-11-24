//! HTTP surface: Host/Origin/auth rejection, security headers, validation, pagination.
//! Covers security acceptance tests 6 (unauthorized access) and 7 (path traversal), HTTP part.

mod common;

use axum::body::Body;
use axum::http::Request;
use cc_workspace_manager::auth::bootstrap::BOOTSTRAP_TTL_SECS;
use cc_workspace_manager::clock::Clock;
use common::{code, env, json, PORT, START};

const DAY: i64 = 24 * 3600;

fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

fn host() -> String {
    format!("127.0.0.1:{PORT}")
}

// ---- health & headers ----------------------------------------------------------------------

#[tokio::test]
async fn health_is_public_and_minimal() {
    let e = env().await;
    let (s, v) = json(e.get("/api/v1/health", None).await).await;
    assert_eq!(s, 200);
    assert_eq!(
        v,
        serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")})
    );
}

#[tokio::test]
async fn security_headers_are_on_every_response_class() {
    let e = env().await;
    let token = e.login().await;
    let expected_csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:{PORT}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let h = host();
    let responses = vec![
        ("200 api", e.get("/api/v1/health", None).await, true),
        (
            "200 authed",
            e.get("/api/v1/stats", Some(&token)).await,
            true,
        ),
        ("401", e.get("/api/v1/stats", None).await, true),
        ("404", e.get("/api/v1/nope", None).await, true),
        (
            "405",
            e.send(req("DELETE", "/api/v1/health", &[("host", &h)]))
                .await,
            true,
        ),
        (
            "421",
            e.send(req("GET", "/api/v1/health", &[("host", "evil.test")]))
                .await,
            true,
        ),
        (
            "403",
            e.send(req(
                "GET",
                "/api/v1/health",
                &[("host", &h), ("origin", "http://evil.test")],
            ))
            .await,
            true,
        ),
        ("static", e.get("/", None).await, false),
        ("static 404", e.get("/missing.js", None).await, false),
    ];
    for (name, resp, is_api) in responses {
        let hd = resp.headers();
        assert_eq!(hd["x-content-type-options"], "nosniff", "{name}");
        assert_eq!(hd["referrer-policy"], "no-referrer", "{name}");
        assert_eq!(hd["cross-origin-opener-policy"], "same-origin", "{name}");
        assert_eq!(
            hd["content-security-policy"],
            expected_csp.as_str(),
            "{name}"
        );
        assert_eq!(
            hd["cache-control"],
            if is_api { "no-store" } else { "no-cache" },
            "{name}"
        );
        assert!(
            !hd.keys().any(|k| k.as_str().starts_with("access-control-")),
            "{name}: no CORS headers, ever"
        );
    }
}

// ---- Host ------------------------------------------------------------------------------------

#[tokio::test]
async fn only_our_loopback_authorities_are_accepted_as_host() {
    let e = env().await;
    for ok in [
        format!("127.0.0.1:{PORT}"),
        format!("localhost:{PORT}"),
        format!("[::1]:{PORT}"),
        format!("LOCALHOST:{PORT}"),
    ] {
        let resp = e.send(req("GET", "/api/v1/health", &[("host", &ok)])).await;
        assert_eq!(resp.status(), 200, "{ok}");
    }
    for bad in [
        "evil.test",
        "evil.test:18765",
        "127.0.0.1",
        "127.0.0.1:1",
        "localhost",
        "127.0.0.1:18765.evil.test",
        "0.0.0.0:18765",
        "[::1]",
        "127.0.0.1:18765, evil.test",
        "",
    ] {
        let (s, v) = json(e.send(req("GET", "/api/v1/health", &[("host", bad)])).await).await;
        assert_eq!((s, code(&v)), (421, "host_not_allowed"), "{bad:?}");
    }
}

#[tokio::test]
async fn missing_or_duplicate_host_is_rejected_even_for_static_assets() {
    let e = env().await;
    let (s, _) = json(e.send(req("GET", "/", &[])).await).await;
    assert_eq!(s, 421);
    let (s, _) = json(
        e.send(req("GET", "/", &[("host", &host()), ("host", "evil.test")]))
            .await,
    )
    .await;
    assert_eq!(s, 421);
    let (s, _) = json(
        e.send(req("GET", "/app.js", &[("host", "evil.test")]))
            .await,
    )
    .await;
    assert_eq!(s, 421);
    // an absolute-form target for another authority is not served either
    let (s, _) = json(
        e.send(req(
            "GET",
            "http://evil.test/api/v1/health",
            &[("host", &host())],
        ))
        .await,
    )
    .await;
    assert_eq!(s, 421);
}

// ---- Origin ----------------------------------------------------------------------------------

#[tokio::test]
async fn origin_rules() {
    let e = env().await;
    let h = host();
    let good = format!("http://127.0.0.1:{PORT}");
    // GET without Origin is fine (same-origin navigation, curl, health probes)
    assert_eq!(
        e.send(req("GET", "/api/v1/health", &[("host", &h)]))
            .await
            .status(),
        200
    );
    assert_eq!(
        e.send(req(
            "GET",
            "/api/v1/health",
            &[("host", &h), ("origin", &good)]
        ))
        .await
        .status(),
        200
    );
    // any other Origin is rejected, even on GET
    for bad in [
        "http://evil.test",
        "null",
        "http://localhost:18765",
        "https://127.0.0.1:18765",
        "http://127.0.0.1:1",
        "http://127.0.0.1:18765/",
        "http://127.0.0.1:18765.evil.test",
        "",
    ] {
        let (s, v) = json(
            e.send(req(
                "GET",
                "/api/v1/health",
                &[("host", &h), ("origin", bad)],
            ))
            .await,
        )
        .await;
        assert_eq!((s, code(&v)), (403, "origin_not_allowed"), "{bad:?}");
    }
    // two Origin headers
    let (s, _) = json(
        e.send(req(
            "GET",
            "/api/v1/health",
            &[("host", &h), ("origin", &good), ("origin", &good)],
        ))
        .await,
    )
    .await;
    assert_eq!(s, 403);
}

#[tokio::test]
async fn state_changing_requests_need_the_allowed_origin() {
    let e = env().await;
    let token = e.login().await;
    let h = host();
    let auth = format!("Bearer {token}");
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let (s, v) = json(
            e.send(req(
                method,
                "/api/v1/auth/logout",
                &[("host", &h), ("authorization", &auth)],
            ))
            .await,
        )
        .await;
        assert_eq!(
            (s, code(&v)),
            (403, "origin_not_allowed"),
            "{method} without Origin"
        );
    }
    let (s, v) = json(
        e.send(req(
            "POST",
            "/api/v1/auth/logout",
            &[
                ("host", &h),
                ("authorization", &auth),
                ("origin", "http://evil.test"),
            ],
        ))
        .await,
    )
    .await;
    assert_eq!((s, code(&v)), (403, "origin_not_allowed"));
    // the session survived all those attempts
    assert_eq!(e.get("/api/v1/stats", Some(&token)).await.status(), 200);
}

// ---- authentication ---------------------------------------------------------------------------

#[tokio::test]
async fn protected_endpoints_reject_missing_malformed_and_unknown_tokens() {
    let e = env().await;
    for path in [
        "/api/v1/projects",
        "/api/v1/stats",
        "/api/v1/discovery/status",
        "/api/v1/service/status",
    ] {
        for (label, token) in [
            ("none", None),
            ("empty", Some("")),
            ("short", Some("abc")),
            ("unknown", Some("A".repeat(43).leak() as &str)),
            ("garbage", Some("%%%%")),
        ] {
            let (s, v) = json(e.get(path, token).await).await;
            assert_eq!((s, code(&v)), (401, "unauthorized"), "{path} {label}");
        }
    }
    // every failure has the same message, so responses reveal nothing
    let (_, a) = json(e.get("/api/v1/stats", None).await).await;
    let (_, b) = json(e.get("/api/v1/stats", Some(&"A".repeat(43))).await).await;
    assert_eq!(a, b);
}

#[tokio::test]
async fn wrong_authorization_schemes_and_duplicate_headers_are_rejected() {
    let e = env().await;
    let token = e.login().await;
    let h = host();
    for value in [
        format!("Basic {token}"),
        token.clone(),
        format!("Bearer{token}"),
        format!("Token {token}"),
    ] {
        let (s, _) = json(
            e.send(req(
                "GET",
                "/api/v1/stats",
                &[("host", &h), ("authorization", &value)],
            ))
            .await,
        )
        .await;
        assert_eq!(s, 401, "{value}");
    }
    let (s, _) = json(
        e.send(req(
            "GET",
            "/api/v1/stats",
            &[
                ("host", &h),
                ("authorization", &format!("Bearer {token}")),
                ("authorization", &format!("Bearer {token}")),
            ],
        ))
        .await,
    )
    .await;
    assert_eq!(s, 401, "ambiguous duplicate Authorization headers");
    let (s, _) = json(
        e.send(req(
            "GET",
            "/api/v1/stats",
            &[("host", &h), ("authorization", &format!("bearer {token}"))],
        ))
        .await,
    )
    .await;
    assert_eq!(s, 200, "the scheme is case-insensitive");
}

/// Rotate over HTTP; `None` if refused.
async fn rotate(e: &common::Env, token: &str) -> Option<String> {
    let (s, v) = json(e.post("/api/v1/auth/rotate", Some(token), "").await).await;
    (s == 200).then(|| v["session_token"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn expired_tokens_are_rejected_and_use_slides_the_expiry() {
    let e = env().await;
    let token = e.login().await;
    e.clock.advance(20 * DAY);
    let token = rotate(&e, &token).await.expect("rotation slides to day 50");
    assert_eq!(e.get("/api/v1/stats", Some(&token)).await.status(), 200);
    e.writer.flush().await.unwrap();
    e.clock.advance(20 * DAY); // day 40 since login: valid only because of the slide
    let token = rotate(&e, &token).await.expect("still valid on day 40");
    assert_eq!(e.get("/api/v1/stats", Some(&token)).await.status(), 200);
    e.writer.flush().await.unwrap();
    e.clock.advance(31 * DAY);
    let (s, v) = json(e.get("/api/v1/stats", Some(&token)).await).await;
    assert_eq!((s, code(&v)), (401, "unauthorized"));
    assert_eq!(
        rotate(&e, &token).await,
        None,
        "an expired token cannot rotate"
    );
}

#[tokio::test]
async fn an_unused_token_expires_after_thirty_days() {
    let e = env().await;
    let token = e.login().await;
    e.clock.advance(30 * DAY - 1);
    assert!(rotate(&e, &token).await.is_some());
    let e2 = env().await;
    let token2 = e2.login().await;
    e2.clock.advance(30 * DAY);
    assert_eq!(rotate(&e2, &token2).await, None);
    assert_eq!(e2.get("/api/v1/stats", Some(&token2)).await.status(), 401);
}

/// L1: once rotation is overdue (24 h + 60 s slack), the token works only on /auth/rotate.
#[tokio::test]
async fn an_overdue_token_is_accepted_only_for_rotation() {
    let e = env().await;
    let token = e.login().await;
    e.clock.advance(DAY + 59);
    assert_eq!(
        e.get("/api/v1/stats", Some(&token)).await.status(),
        200,
        "inside the slack after rotate_after"
    );
    e.clock.advance(1);
    for path in [
        "/api/v1/stats",
        "/api/v1/projects",
        "/api/v1/service/status",
    ] {
        let (s, v) = json(e.get(path, Some(&token)).await).await;
        assert_eq!((s, code(&v)), (401, "unauthorized"), "{path}");
    }
    assert_eq!(
        e.post("/api/v1/auth/logout", Some(&token), "")
            .await
            .status(),
        401
    );
    let fresh = rotate(&e, &token).await.expect("rotation is still allowed");
    assert_eq!(e.get("/api/v1/stats", Some(&fresh)).await.status(), 200);
    // The overdue token keeps only its 60 s rotation grace, like any rotated-out token.
    assert_eq!(e.get("/api/v1/stats", Some(&token)).await.status(), 200);
    e.clock.advance(60);
    assert_eq!(e.get("/api/v1/stats", Some(&token)).await.status(), 401);
}

#[tokio::test]
async fn logout_revokes_the_session_and_revoke_all_revokes_every_session() {
    let e = env().await;
    let (a, b, c) = (e.login().await, e.login().await, e.login().await);
    assert_eq!(
        e.post("/api/v1/auth/logout", Some(&a), "").await.status(),
        204
    );
    assert_eq!(e.get("/api/v1/stats", Some(&a)).await.status(), 401);
    assert_eq!(e.get("/api/v1/stats", Some(&b)).await.status(), 200);
    assert_eq!(e.service.auth_revoke_all().await.unwrap(), 2);
    for t in [&b, &c] {
        assert_eq!(e.get("/api/v1/stats", Some(t)).await.status(), 401);
    }
    assert_eq!(
        e.post("/api/v1/auth/logout", Some(&a), "").await.status(),
        401,
        "logout twice"
    );
}

#[tokio::test]
async fn rotation_issues_a_new_token_and_keeps_the_old_one_for_sixty_seconds() {
    let e = env().await;
    let old = e.login().await;
    e.clock.advance(100);
    let (s, v) = json(e.post("/api/v1/auth/rotate", Some(&old), "").await).await;
    assert_eq!(s, 200);
    let new = v["session_token"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    assert_eq!(v["rotate_after"].as_i64().unwrap(), START + 100 + DAY);
    assert_eq!(e.get("/api/v1/stats", Some(&new)).await.status(), 200);
    e.clock.advance(59);
    assert_eq!(
        e.get("/api/v1/stats", Some(&old)).await.status(),
        200,
        "inside the grace window"
    );
    // the previous token cannot rotate again
    assert_eq!(
        e.post("/api/v1/auth/rotate", Some(&old), "").await.status(),
        401
    );
    e.clock.advance(1);
    assert_eq!(
        e.get("/api/v1/stats", Some(&old)).await.status(),
        401,
        "grace over"
    );
    assert_eq!(e.get("/api/v1/stats", Some(&new)).await.status(), 200);
    // logging out with the new token also kills the (already dead) old one and itself
    assert_eq!(
        e.post("/api/v1/auth/logout", Some(&new), "").await.status(),
        204
    );
    assert_eq!(e.get("/api/v1/stats", Some(&new)).await.status(), 401);
}

// ---- bootstrap / exchange ------------------------------------------------------------------------

#[tokio::test]
async fn exchange_consumes_the_bootstrap_token() {
    let e = env().await;
    let b = e.service.auth_bootstrap().unwrap();
    assert_eq!((b.expires_in, b.port), (BOOTSTRAP_TTL_SECS, PORT));
    assert_eq!(BOOTSTRAP_TTL_SECS, 30);
    let body = format!(r#"{{"bootstrap_token":"{}"}}"#, b.bootstrap_token);
    let (s, v) = json(e.post("/api/v1/auth/exchange", None, &body).await).await;
    assert_eq!(s, 200);
    let token = v["session_token"].as_str().unwrap();
    assert_eq!(token.len(), 43);
    assert_eq!(v["expires_at"].as_i64().unwrap(), START + 30 * DAY);
    assert_eq!(v["rotate_after"].as_i64().unwrap(), START + DAY);
    assert_eq!(e.get("/api/v1/stats", Some(token)).await.status(), 200);
    // second use
    let (s, v) = json(e.post("/api/v1/auth/exchange", None, &body).await).await;
    assert_eq!((s, code(&v)), (401, "unauthorized"));
}

#[tokio::test]
async fn exchange_rejects_expired_unknown_and_malformed_requests() {
    let e = env().await;
    let b = e.service.auth_bootstrap().unwrap();
    e.clock.advance(60);
    let post = |body: String| {
        let e = &e;
        async move { json(e.post("/api/v1/auth/exchange", None, &body).await).await }
    };
    let (s, _) = post(format!(r#"{{"bootstrap_token":"{}"}}"#, b.bootstrap_token)).await;
    assert_eq!(s, 401, "expired");
    let (s, _) = post(format!(r#"{{"bootstrap_token":"{}"}}"#, "A".repeat(43))).await;
    assert_eq!(s, 401, "unknown");
    for bad in [
        "",
        "{}",
        "[]",
        "not json",
        r#"{"bootstrap_token":1}"#,
        r#"{"bootstrap_token":"x","extra":1}"#,
    ] {
        let (s, v) = post(bad.to_string()).await;
        assert_eq!((s, code(&v)), (400, "invalid_argument"), "{bad:?}");
    }
    // wrong content type
    let r = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/exchange")
        .header("host", host())
        .header("origin", format!("http://127.0.0.1:{PORT}"))
        .header("content-type", "text/plain")
        .body(Body::from(r#"{"bootstrap_token":"x"}"#))
        .unwrap();
    assert_eq!(e.send(r).await.status(), 400);
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let e = env().await;
    let big = format!(r#"{{"bootstrap_token":"{}"}}"#, "A".repeat(20_000));
    let (s, v) = json(e.post("/api/v1/auth/exchange", None, &big).await).await;
    assert_eq!((s, code(&v)), (413, "payload_too_large"));
}

#[tokio::test]
async fn error_bodies_never_echo_tokens() {
    let e = env().await;
    let secret = "S".repeat(43);
    let (_, v) = json(e.get("/api/v1/stats", Some(&secret)).await).await;
    assert!(!v.to_string().contains(&secret));
    let (_, v) = json(
        e.post(
            "/api/v1/auth/exchange",
            None,
            &format!(r#"{{"bootstrap_token":"{secret}"}}"#),
        )
        .await,
    )
    .await;
    assert!(!v.to_string().contains(&secret));
}

// ---- routing, methods, traversal ----------------------------------------------------------------

#[tokio::test]
async fn unknown_routes_and_wrong_methods_use_the_json_envelope() {
    let e = env().await;
    let (s, v) = json(e.get("/api/v1/nope", None).await).await;
    assert_eq!((s, code(&v)), (404, "not_found"));
    let (s, v) = json(e.get("/api/v2/health", None).await).await;
    assert_eq!((s, code(&v)), (404, "not_found"));
    let h = host();
    for (method, path) in [
        ("OPTIONS", "/api/v1/health"),
        ("OPTIONS", "/"),
        ("PUT", "/api/v1/projects"),
        ("DELETE", "/api/v1/health"),
        ("GET", "/api/v1/auth/logout"),
    ] {
        let (s, v) = json(
            e.send(req(
                method,
                path,
                &[
                    ("host", &h),
                    ("origin", &format!("http://127.0.0.1:{PORT}")),
                ],
            ))
            .await,
        )
        .await;
        assert_eq!(
            (s, code(&v)),
            (405, "method_not_allowed"),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn traversal_attempts_never_reach_the_filesystem() {
    let e = env().await;
    let token = e.login().await;
    for path in [
        "/../etc/passwd",
        "/..%2fetc%2fpasswd",
        "/%2e%2e/etc/passwd",
        "/app.js/../../etc/passwd",
        "/api/v1/../../etc/passwd",
        "/api/v1/projects/../../../etc/passwd",
        "/api/v1/projects/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "//etc/passwd",
        "/etc/passwd",
        "/web/index.html",
        "/src/main.rs",
        "/Cargo.toml",
    ] {
        let resp = e.get(path, Some(&token)).await;
        let status = resp.status().as_u16();
        let (_, body) = json(resp).await;
        assert!(matches!(status, 400 | 404 | 405), "{path} -> {status}");
        let text = body.to_string();
        assert!(
            !text.contains("root:") && !text.contains("[package]") && !text.contains("fn main"),
            "{path}"
        );
    }
}

// ---- static assets -------------------------------------------------------------------------------

#[tokio::test]
async fn static_assets_are_served_with_correct_types() {
    let e = env().await;
    for (path, ctype) in [
        ("/", "text/html"),
        ("/app.css", "text/css"),
        ("/app.js", "text/javascript"),
    ] {
        let r = e.get(path, None).await;
        assert_eq!(r.status(), 200, "{path}");
        assert!(
            r.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(ctype),
            "{path}"
        );
    }
    let body = axum::body::to_bytes(e.get("/", None).await.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        html.contains("independent, unofficial")
            && html.contains("not affiliated with or endorsed by Anthropic")
    );
    assert!(
        !html.contains("<script>") && !html.contains(" style=") && !html.contains("onclick"),
        "no inline script/style (CSP)"
    );
}

// ---- data endpoints --------------------------------------------------------------------------------

#[tokio::test]
async fn projects_listing_validation_and_pagination() {
    let e = env().await;
    let token = e.login().await;
    let names: Vec<String> = (0..7).map(|i| format!("proj{i}")).collect();
    e.seed(&names.iter().map(String::as_str).collect::<Vec<_>>())
        .await;

    let (s, v) = json(e.get("/api/v1/projects", Some(&token)).await).await;
    assert_eq!(
        (s, v["total"].as_u64(), v["items"].as_array().unwrap().len()),
        (200, Some(7), 7)
    );
    assert!(v["next_cursor"].is_null());
    let first = &v["items"][0];
    for key in ["id", "name", "path", "sources", "first_seen_at"] {
        assert!(first.get(key).is_some(), "{key}");
    }
    assert_eq!(first["name"], "proj0");
    assert_eq!(first["sources"], serde_json::json!(["marker"]));

    // walk pages of 3 with the cursor
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let url = match &cursor {
            Some(c) => format!("/api/v1/projects?limit=3&cursor={c}"),
            None => "/api/v1/projects?limit=3".to_string(),
        };
        let (s, v) = json(e.get(&url, Some(&token)).await).await;
        assert_eq!(s, 200);
        seen.extend(
            v["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["name"].as_str().unwrap().to_string()),
        );
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen, names);

    // descending name sort
    let (_, v) = json(
        e.get(
            "/api/v1/projects?sort=name&order=desc&limit=2",
            Some(&token),
        )
        .await,
    )
    .await;
    assert_eq!(v["items"][0]["name"], "proj6");
    // search
    let (_, v) = json(e.get("/api/v1/projects?q=PROJ3", Some(&token)).await).await;
    assert_eq!(
        (v["total"].as_u64(), v["items"][0]["name"].as_str()),
        (Some(1), Some("proj3"))
    );
}

#[tokio::test]
async fn projects_query_validation_errors() {
    let e = env().await;
    let token = e.login().await;
    for bad in [
        "limit=0",
        "limit=201",
        "limit=abc",
        "limit=",
        "sort=bogus",
        "order=up",
        "activity=today",
        "dirty=true",
        "has_sessions=1",
        "include_missing=1",
        "privacy=1",
        "unknown=1",
        "cursor=!!!",
        "cursor=eyJzIjoibmFtZSJ9",
        "limit=1&limit=2",
        "q=a%00b",
    ] {
        let (s, v) = json(
            e.get(&format!("/api/v1/projects?{bad}"), Some(&token))
                .await,
        )
        .await;
        assert_eq!((s, code(&v)), (400, "invalid_argument"), "{bad}");
    }
    // a cursor from one sort/order is not accepted by another
    e.seed(&["a", "b", "c"]).await;
    let (_, v) = json(
        e.get("/api/v1/projects?sort=name&limit=1", Some(&token))
            .await,
    )
    .await;
    let c = v["next_cursor"].as_str().unwrap().to_string();
    let (s, _) = json(
        e.get(
            &format!("/api/v1/projects?sort=name&order=desc&cursor={c}"),
            Some(&token),
        )
        .await,
    )
    .await;
    assert_eq!(s, 400);
    let (s, _) = json(
        e.get(
            &format!("/api/v1/projects?sort=name&cursor={c}"),
            Some(&token),
        )
        .await,
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn stats_discovery_and_service_status_shapes() {
    let e = env().await;
    let token = e.login().await;
    e.seed(&["a", "b"]).await;
    let (s, v) = json(e.get("/api/v1/stats", Some(&token)).await).await;
    assert_eq!((s, v), (200, serde_json::json!({"total_projects": 2})));
    let (s, v) = json(e.get("/api/v1/discovery/status", Some(&token)).await).await;
    assert_eq!(s, 200);
    for key in [
        "phase",
        "dirs_visited",
        "projects_found",
        "skipped",
        "roots",
        "last_success_at",
        "next_scan_at",
    ] {
        assert!(v.get(key).is_some(), "{key}");
    }
    assert_eq!(v["phase"], "idle");
    let (s, v) = json(e.get("/api/v1/service/status", Some(&token)).await).await;
    assert_eq!(s, 200);
    assert_eq!(v["port"], PORT);
    assert_eq!(v["sandbox"]["status"], "not_enforced");
    assert!(v["uptime_s"].as_i64().unwrap() >= 0);
    e.clock.advance(90);
    let (_, v) = json(e.get("/api/v1/service/status", Some(&token)).await).await;
    assert_eq!(v["uptime_s"], 90);
}

// ---- web/ source hygiene --------------------------------------------------------------------------------

#[test]
fn web_sources_never_use_dangerous_dom_apis() {
    let banned = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setAttribute(\"style\"",
        "setAttribute('style'",
        "javascript:",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("web");
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for b in banned {
            assert!(!text.contains(b), "{} contains {b}", path.display());
        }
        checked += 1;
    }
    assert!(checked >= 3);
}

// ---- M1.1: rotation races, grace window, session cap ------------------------------------------------

#[tokio::test]
async fn two_concurrent_rotations_with_the_same_token_yield_exactly_one_new_token() {
    let e = env().await;
    let token = e.login().await;
    let (a, b) = tokio::join!(rotate(&e, &token), rotate(&e, &token));
    let winners: Vec<String> = [a, b].into_iter().flatten().collect();
    assert_eq!(
        winners.len(),
        1,
        "rotation is atomic: one wins, the other is refused"
    );
    let new = &winners[0];
    assert_eq!(e.get("/api/v1/stats", Some(new)).await.status(), 200);
    assert_eq!(
        e.get("/api/v1/stats", Some(&token)).await.status(),
        200,
        "the old token is still inside its grace window"
    );
    assert_eq!(
        rotate(&e, &token).await,
        None,
        "a rotated-out token cannot rotate"
    );
}

#[tokio::test]
async fn logout_with_the_old_token_during_the_grace_window_ends_the_whole_session() {
    let e = env().await;
    let old = e.login().await;
    let new = rotate(&e, &old).await.unwrap();
    assert_eq!(
        e.post("/api/v1/auth/logout", Some(&old), "").await.status(),
        204
    );
    for t in [&old, &new] {
        assert_eq!(e.get("/api/v1/stats", Some(t)).await.status(), 401);
    }
}

#[tokio::test]
async fn revoke_all_during_the_grace_window_kills_both_tokens() {
    let e = env().await;
    let old = e.login().await;
    let new = rotate(&e, &old).await.unwrap();
    let other = e.login().await;
    assert_eq!(e.service.auth_revoke_all().await.unwrap(), 2);
    for t in [&old, &new, &other] {
        assert_eq!(e.get("/api/v1/stats", Some(t)).await.status(), 401);
    }
}

/// L3: at most 10 live sessions; the least recently used one is revoked, the others survive.
#[tokio::test]
async fn an_eleventh_session_revokes_the_least_recently_used_one() {
    let e = env().await;
    let mut tokens = Vec::new();
    for _ in 0..cc_workspace_manager::db::writer::MAX_LIVE_SESSIONS {
        tokens.push(e.login().await);
        e.clock.advance(1);
    }
    // Use the oldest session so that the second-oldest becomes the least recently used.
    e.clock
        .advance(cc_workspace_manager::auth::sessions::TOUCH_INTERVAL_SECS);
    assert_eq!(e.get("/api/v1/stats", Some(&tokens[0])).await.status(), 200);
    e.writer.flush().await.unwrap();
    let newest = e.login().await;
    assert_eq!(e.get("/api/v1/stats", Some(&newest)).await.status(), 200);
    assert_eq!(e.get("/api/v1/stats", Some(&tokens[0])).await.status(), 200);
    assert_eq!(
        e.get("/api/v1/stats", Some(&tokens[1])).await.status(),
        401,
        "least recently used"
    );
    for t in &tokens[2..] {
        assert_eq!(e.get("/api/v1/stats", Some(t)).await.status(), 200);
    }
}

#[tokio::test]
async fn creating_a_session_purges_expired_ones_first_and_purge_runs_on_demand() {
    let e = env().await;
    let stale = e.login().await;
    e.clock.advance(31 * DAY);
    let fresh = e.login().await;
    assert_eq!(e.get("/api/v1/stats", Some(&fresh)).await.status(), 200);
    let count = e
        .service
        .reader
        .with(cc_workspace_manager::db::queries::count_sessions)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "the expired session was purged when the new one was created"
    );
    assert_eq!(e.get("/api/v1/stats", Some(&stale)).await.status(), 401);
    e.clock.advance(31 * DAY);
    assert_eq!(
        e.writer
            .purge_expired_sessions(e.clock.now())
            .await
            .unwrap(),
        1
    );
}

// ---- M1.1: TCP peer UID, connection cap, header timeout (real sockets) ----------------------------

mod sockets {
    use super::common::{self, PORT};
    use cc_workspace_manager::http::{self, peer::PeerUidLookup, ServeOptions};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    struct Server {
        addr: SocketAddr,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
        _env: common::Env,
    }

    impl Server {
        async fn stop(mut self) {
            let _ = self.stop.take().unwrap().send(());
            self.task.await.unwrap().unwrap();
        }
    }

    async fn serve(lookup: PeerUidLookup, max: usize, header_timeout: Duration) -> Server {
        let env = common::env().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let opts = ServeOptions {
            daemon_uid: me(),
            peer_uid: lookup,
            max_connections: max,
            header_read_timeout: header_timeout,
        };
        let task = tokio::spawn(http::serve(listener, env.service.clone(), opts, async {
            let _ = rx.await;
        }));
        Server {
            addr,
            stop: Some(tx),
            task,
            _env: env,
        }
    }

    /// Send a request (Host is the service's port, which the Host check expects) and read it all.
    async fn get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
            .await
            .map_err(|_| std::io::Error::other("timed out"))??;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    #[tokio::test]
    async fn the_real_lookup_serves_our_own_connections() {
        let srv = serve(http::peer::procfs_lookup(), 8, Duration::from_secs(5)).await;
        let resp = get(srv.addr, "/api/v1/health").await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        srv.stop().await;
    }

    /// Test 6: a client socket owned by another UID (simulated lookup) gets no response at all,
    /// not even for public endpoints; so do unknown owners and failed lookups.
    #[tokio::test]
    async fn connections_from_another_uid_or_an_unknown_owner_are_closed_unanswered() {
        let other = me() + 1;
        let lookups: [PeerUidLookup; 3] = [
            Arc::new(move |_, _| Ok(Some(other))),
            Arc::new(|_, _| Ok(None)),
            Arc::new(|_, _| Err(std::io::Error::other("procfs unreadable"))),
        ];
        for lookup in lookups {
            let srv = serve(lookup, 8, Duration::from_secs(5)).await;
            for path in ["/api/v1/health", "/", "/api/v1/projects"] {
                match get(srv.addr, path).await {
                    Ok(resp) => assert!(resp.is_empty(), "{path}: got {resp:?}"),
                    Err(e) => assert!(
                        matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                        ),
                        "{path}: {e}"
                    ),
                }
            }
            srv.stop().await;
        }
    }

    #[tokio::test]
    async fn the_lookup_sees_the_client_and_server_addresses_and_runs_once_per_connection() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (c, s2) = (Arc::clone(&calls), Arc::clone(&seen));
        let lookup: PeerUidLookup = Arc::new(move |client, server| {
            c.fetch_add(1, Ordering::SeqCst);
            s2.lock().unwrap().push((client, server));
            Ok(Some(nix::unistd::geteuid().as_raw()))
        });
        let srv = serve(lookup, 8, Duration::from_secs(5)).await;
        // Two requests on one keep-alive connection: one lookup.
        let mut s = TcpStream::connect(srv.addr).await.unwrap();
        let local = s.local_addr().unwrap();
        let req = format!("GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n");
        let close = format!(
            "GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        s.write_all(close.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out.matches("HTTP/1.1 200").count(), 2, "{out}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(seen.lock().unwrap()[0], (local, srv.addr));
        srv.stop().await;
    }

    /// L5: a client that never completes its request head is disconnected.
    #[tokio::test]
    async fn incomplete_request_heads_time_out() {
        let srv = serve(http::peer::procfs_lookup(), 8, Duration::from_millis(500)).await;
        for partial in ["", "GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1"] {
            let mut s = TcpStream::connect(srv.addr).await.unwrap();
            s.write_all(partial.as_bytes()).await.unwrap();
            let started = Instant::now();
            let mut buf = Vec::new();
            let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
            assert!(r.is_ok(), "the server kept a stalled connection open");
            assert!(
                started.elapsed() >= Duration::from_millis(400),
                "closed too early"
            );
            let text = String::from_utf8_lossy(&buf);
            assert!(!text.contains("200"), "{text}");
        }
        srv.stop().await;
    }

    /// L5: the connection cap holds extra clients in the backlog until a slot frees up.
    #[tokio::test]
    async fn the_connection_cap_queues_extra_clients_until_a_slot_frees() {
        let srv = serve(http::peer::procfs_lookup(), 2, Duration::from_secs(30)).await;
        let a = TcpStream::connect(srv.addr).await.unwrap();
        let b = TcpStream::connect(srv.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let addr = srv.addr;
        let third = tokio::spawn(async move { get(addr, "/api/v1/health").await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !third.is_finished(),
            "the third client must wait for a slot"
        );
        drop(a);
        let resp = tokio::time::timeout(Duration::from_secs(5), third)
            .await
            .expect("served once a slot was free")
            .unwrap()
            .unwrap();
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        drop(b);
        srv.stop().await;
    }

    #[tokio::test]
    async fn shutdown_completes_even_with_idle_connections_open() {
        let srv = serve(http::peer::procfs_lookup(), 8, Duration::from_secs(30)).await;
        let _idle = TcpStream::connect(srv.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        srv.stop().await;
        assert!(started.elapsed() < Duration::from_secs(7));
    }
}

/// L8: the cursor and ORDER BY share one stored normalization, so non-ASCII names are neither
/// skipped nor repeated across pages, in both directions.
#[tokio::test]
async fn pagination_over_non_ascii_names_visits_every_project_exactly_once() {
    let e = env().await;
    let names = [
        "École",
        "ecole2",
        "Éclair",
        "ÉZ",
        "éa",
        "Ärger",
        "apfel",
        "Zebra",
        "zz",
        "Ωmega",
        "ωa",
        "İstanbul",
        "istanbul",
        "ß",
        "SS",
        "ǅemal",
    ];
    e.seed(&names).await;
    let token = e.login().await;
    for (order, limit) in [("asc", 1), ("asc", 2), ("desc", 3)] {
        let mut seen = Vec::new();
        let mut cursor = String::new();
        loop {
            let path = format!("/api/v1/projects?sort=name&order={order}&limit={limit}{cursor}");
            let (s, v) = json(e.get(&path, Some(&token)).await).await;
            assert_eq!(s, 200, "{v}");
            for item in v["items"].as_array().unwrap() {
                seen.push(item["name"].as_str().unwrap().to_string());
            }
            match v["next_cursor"].as_str() {
                Some(c) => cursor = format!("&cursor={c}"),
                None => break,
            }
        }
        let mut want: Vec<String> = names.iter().map(ToString::to_string).collect();
        want.sort_by_key(|n| cc_workspace_manager::db::sort_key(n));
        if order == "desc" {
            want.reverse();
        }
        assert_eq!(seen.len(), names.len(), "{order}/{limit}: {seen:?}");
        let mut a = seen.clone();
        a.sort();
        let mut b = want.clone();
        b.sort();
        assert_eq!(a, b, "{order}/{limit}: every name exactly once");
        let keys: Vec<String> = seen
            .iter()
            .map(|n| cc_workspace_manager::db::sort_key(n))
            .collect();
        let want_keys: Vec<String> = want
            .iter()
            .map(|n| cc_workspace_manager::db::sort_key(n))
            .collect();
        assert_eq!(keys, want_keys, "{order}/{limit}: sorted by the stored key");
    }
}
