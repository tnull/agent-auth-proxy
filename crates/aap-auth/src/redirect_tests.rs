use super::*;
use http_body_util::Full;
fn response(status: u16, location: &str) -> Response {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("location", location)
        .header("set-cookie", "session=cookie-secret; Secure; Path=/")
        .body(
            Full::new(Bytes::from_static(
                br#"{"echo":"password-secret cookie-secret"}"#,
            ))
            .map_err(|never| match never {})
            .boxed_unsync(),
        )
        .unwrap()
}
fn redactor() -> Redactor {
    Redactor::new(&[b"password-secret"]).unwrap()
}
#[tokio::test]
async fn only_exact_authorized_303_locations_survive_response_sanitization() {
    let target = "https://example.test/done";
    let result = sanitize_login_redirect(response(303, "/done"), redactor(), target)
        .expect("declared redirect was refused");
    assert_eq!(result.status(), 303);
    assert_eq!(result.headers()["location"], target);
    assert!(!result.headers().contains_key("set-cookie"));
    assert_eq!(
        result.into_body().collect().await.unwrap().to_bytes(),
        br#"{"echo":"[redacted] [redacted]"}"#[..]
    );
    for status in [200, 301, 302, 307, 308] {
        assert!(sanitize_login_redirect(response(status, target), redactor(), target).is_err());
    }
    for location in [
        "https://other.test/done",
        "//other.test/done",
        "/done?password=password-secret",
        "/done#password-secret",
        "/other",
    ] {
        assert!(sanitize_login_redirect(response(303, location), redactor(), target).is_err());
    }
    for target in [
        "http://example.test/done",
        "https://example.test/password-secret",
        "https://example.test/cookie-secret",
    ] {
        assert!(sanitize_login_redirect(response(303, target), redactor(), target).is_err());
    }
    let mut duplicate = response(303, target);
    duplicate
        .headers_mut()
        .append("location", target.parse().unwrap());
    assert!(sanitize_login_redirect(duplicate, redactor(), target).is_err());
    assert!(
        sanitize_response(response(303, target), redactor()).is_err(),
        "default response path became redirect-permissive"
    );
}
