//! Bounded, structural login substitution. Session/grant/lease checks belong to
//! the engine; these transforms never authorize a destination or read a store.
use crate::Redactor;
use aap_secrets::{Field, Snapshot};
use aap_types::{
    ErrorCode, Result,
    profile::{CsrfProfile, LoginEncoding, LoginProfile},
};
use bytes::Bytes;
use serde_json::Value;

const MAX_BODY: usize = 256 * 1024;

pub struct Placeholders {
    username: String,
    password: String,
}
impl Placeholders {
    pub fn new() -> Result<Self> {
        Ok(Self {
            username: format!(
                "aap_un1_{}",
                aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?
            ),
            password: format!(
                "aap_pw1_{}",
                aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?
            ),
        })
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}
/// Private page state. Construct a new value for every new upstream token;
/// replacing it in a context invalidates previous submitted placeholders.
pub struct CsrfToken {
    placeholder: String,
    value: String,
}
impl CsrfToken {
    /// Virtualizes the exact declared JSON string. Other fields are not trusted
    /// by this transform: the caller must still sanitize cookies/response data.
    pub fn from_page(profile: &CsrfProfile, body: &[u8]) -> Result<(Self, Bytes)> {
        if body.len() > MAX_BODY {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let mut document: Value =
            aap_types::json::decode(body).map_err(|_| ErrorCode::RequestInvalid)?;
        if !profile.response_pointer.starts_with('/') {
            return Err(ErrorCode::RequestInvalid.into());
        }
        let target = document
            .pointer_mut(&profile.response_pointer)
            .ok_or(ErrorCode::RequestInvalid)?;
        let value = target
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .ok_or(ErrorCode::RequestInvalid)?
            .to_owned();
        let placeholder = format!(
            "aap_cs1_{}",
            aap_types::ids::random_id(32).map_err(|_| ErrorCode::InternalError)?
        );
        *target = Value::String(placeholder.clone());
        let body = serde_json::to_vec(&document).map_err(|_| ErrorCode::InternalError)?;
        if body.len() > MAX_BODY {
            return Err(ErrorCode::LimitExceeded.into());
        }
        Ok((Self { placeholder, value }, body.into()))
    }
    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }
    pub fn redactor(&self) -> Result<Redactor> {
        Redactor::new(&[self.value.as_bytes()])
    }
}

/// Contains a completely validated body, but not a password. It has no debug
/// or serialization implementation; substitution produces private wire bytes.
pub struct ValidatedLogin {
    document: Document,
    username: String,
    password: String,
    csrf: Option<(String, String)>,
}
impl ValidatedLogin {
    /// Canonical logical input with credential/CSRF selectors structurally
    /// redacted. No snapshot or native password is needed to construct it.
    pub fn observation(&self) -> Result<Bytes> {
        let mut document = self.document.clone();
        document.put(&self.username, "[redacted]")?;
        document.put(&self.password, "[redacted]")?;
        if let Some((selector, _)) = &self.csrf {
            document.put(selector, "[redacted]")?;
        }
        document.encode()
    }
    /// Call before resolving the password. This initial adapter virtualizes both
    /// fields; visible-username disclosure requires a separate approved path.
    pub fn parse(
        profile: &LoginProfile,
        content_type: &str,
        body: &[u8],
        values: &Placeholders,
        csrf: Option<&CsrfToken>,
    ) -> Result<Self> {
        if body.len() > MAX_BODY {
            return Err(ErrorCode::LimitExceeded.into());
        }
        if profile.username_visible {
            return Err(ErrorCode::AuthProfileUnsupported.into());
        }
        let mut document = match (profile.encoding, content_type) {
            (LoginEncoding::Form, "application/x-www-form-urlencoded") => {
                Document::Form(parse_form(body)?)
            }
            (LoginEncoding::Json, "application/json") => Document::Json(
                aap_types::json::decode(body).map_err(|_| ErrorCode::RequestInvalid)?,
            ),
            _ => return Err(ErrorCode::AuthProfileUnsupported.into()),
        };
        document.take_expected(&profile.fields.username, values.username())?;
        document.take_expected(&profile.fields.password, values.password())?;
        let csrf = match (&profile.csrf, csrf) {
            (Some(profile), Some(token)) => {
                document.take_expected(&profile.submit_field, token.placeholder())?;
                Some((profile.submit_field.clone(), token.value.clone()))
            }
            (None, None) => None,
            _ => return Err(ErrorCode::PlaceholderInvalid.into()),
        };
        if document.has_reserved_value() {
            return Err(ErrorCode::PlaceholderInvalid.into());
        }
        Ok(Self {
            document,
            username: profile.fields.username.clone(),
            password: profile.fields.password.clone(),
            csrf,
        })
    }
    /// The caller must have pinned/revalidated the snapshot's lease and all
    /// authority immediately before this step. Returned bytes must never enter
    /// an agent or observation view without the corresponding sanitization.
    pub fn substitute(mut self, snapshot: &Snapshot) -> Result<(Bytes, Redactor)> {
        let username = snapshot.field(Field::Username)?.expose();
        let password = snapshot.field(Field::Password)?.expose();
        let mut secrets = vec![username, password];
        if let Some((_, value)) = &self.csrf {
            secrets.push(value.as_bytes());
        }
        let redactor = Redactor::new(&secrets)?;
        let username =
            std::str::from_utf8(username).map_err(|_| ErrorCode::AuthProfileUnsupported)?;
        let password =
            std::str::from_utf8(password).map_err(|_| ErrorCode::AuthProfileUnsupported)?;
        self.document.put(&self.username, username)?;
        self.document.put(&self.password, password)?;
        if let Some((selector, value)) = self.csrf {
            self.document.put(&selector, &value)?;
        }
        Ok((self.document.encode()?, redactor))
    }
}

#[derive(Clone)]
enum Document {
    Form(Vec<(String, String)>),
    Json(Value),
}
impl Document {
    fn encode(self) -> Result<Bytes> {
        let bytes = match self {
            Self::Form(fields) => form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&fields)
                .finish()
                .into_bytes(),
            Self::Json(value) => {
                serde_json::to_vec(&value).map_err(|_| ErrorCode::InternalError)?
            }
        };
        if bytes.len() > MAX_BODY {
            return Err(ErrorCode::LimitExceeded.into());
        }
        Ok(bytes.into())
    }
    fn take_expected(&mut self, selector: &str, expected: &str) -> Result<()> {
        if selector.is_empty() {
            return Err(ErrorCode::RequestInvalid.into());
        }
        match self {
            Self::Form(fields) => {
                let (_, value) = fields
                    .iter_mut()
                    .find(|(name, _)| name == selector)
                    .ok_or(ErrorCode::PlaceholderInvalid)?;
                if value != expected {
                    return Err(ErrorCode::PlaceholderInvalid.into());
                }
                value.clear();
            }
            Self::Json(document) => {
                if !selector.starts_with('/') {
                    return Err(ErrorCode::RequestInvalid.into());
                }
                let value = document
                    .pointer_mut(selector)
                    .ok_or(ErrorCode::PlaceholderInvalid)?;
                if value.as_str() != Some(expected) {
                    return Err(ErrorCode::PlaceholderInvalid.into());
                }
                *value = Value::Null;
            }
        }
        Ok(())
    }
    fn put(&mut self, selector: &str, value: &str) -> Result<()> {
        match self {
            Self::Form(fields) => {
                fields
                    .iter_mut()
                    .find(|(name, _)| name == selector)
                    .ok_or(ErrorCode::InternalError)?
                    .1 = value.to_owned()
            }
            Self::Json(document) => {
                *document
                    .pointer_mut(selector)
                    .ok_or(ErrorCode::InternalError)? = Value::String(value.to_owned())
            }
        }
        Ok(())
    }
    fn has_reserved_value(&self) -> bool {
        match self {
            Self::Form(fields) => fields
                .iter()
                .any(|(name, value)| reserved(name) || reserved(value)),
            Self::Json(value) => json_reserved(value),
        }
    }
}
/// Checks decoded application data, not opaque network bytes. Headers and URI
/// admission remain the engine's responsibility.
pub fn reserved(value: &str) -> bool {
    ["aap_pw1_", "aap_un1_", "aap_cs1_"]
        .iter()
        .any(|prefix| value.contains(prefix))
}
fn json_reserved(value: &Value) -> bool {
    match value {
        Value::String(value) => reserved(value),
        Value::Array(values) => values.iter().any(json_reserved),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| reserved(key) || json_reserved(value)),
        _ => false,
    }
}
fn parse_form(body: &[u8]) -> Result<Vec<(String, String)>> {
    let mut fields = Vec::new();
    let mut names = std::collections::HashSet::new();
    for pair in body.split(|byte| *byte == b'&') {
        if fields.len() == 128 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        let equal = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(ErrorCode::RequestInvalid)?;
        let name = decode_component(&pair[..equal])?;
        if name.is_empty() || name.len() > 1024 || !names.insert(name.clone()) {
            return Err(ErrorCode::RequestInvalid.into());
        }
        fields.push((name, decode_component(&pair[equal + 1..])?));
    }
    Ok(fields)
}
fn decode_component(input: &[u8]) -> Result<String> {
    // The standard form parser is deliberately lossy for malformed percent/UTF-8
    // input. Login substitution instead rejects ambiguity before decoding once.
    let mut output = Vec::with_capacity(input.len());
    let mut position = 0;
    while let Some(byte) = input.get(position) {
        match byte {
            b'+' => output.push(b' '),
            b'%' => {
                let high = input
                    .get(position + 1)
                    .and_then(|byte| (*byte as char).to_digit(16))
                    .ok_or(ErrorCode::RequestInvalid)?;
                let low = input
                    .get(position + 2)
                    .and_then(|byte| (*byte as char).to_digit(16))
                    .ok_or(ErrorCode::RequestInvalid)?;
                output.push((high * 16 + low) as u8);
                position += 2;
            }
            byte => output.push(*byte),
        }
        position += 1;
    }
    String::from_utf8(output).map_err(|_| ErrorCode::RequestInvalid.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aap_secrets::{Field, ItemMetadata, Lease, SecretBytes, Version};
    use aap_types::{
        CredentialFields,
        profile::{LoginEncoding, LoginSuccess},
    };
    use serde_json::{Value, json};
    fn profile(encoding: LoginEncoding) -> LoginProfile {
        let fields = match encoding {
            LoginEncoding::Form => CredentialFields {
                username: "user".into(),
                password: "password".into(),
            },
            LoginEncoding::Json => CredentialFields {
                username: "/credentials/user".into(),
                password: "/credentials/password".into(),
            },
        };
        LoginProfile {
            page: "https://fixture.test/login".into(),
            target: "https://fixture.test/session".into(),
            encoding,
            fields,
            username_visible: false,
            post_login_redirect: None,
            success: LoginSuccess {
                status: 200,
                cookie_names: vec!["session".into()],
                json_pointer: "/authenticated".into(),
                expected: json!(true),
            },
            csrf: None,
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot::new(
            ItemMetadata {
                lease: Lease {
                    version: Version::fresh().unwrap(),
                    generation: Version::fresh().unwrap(),
                },
                fields: vec![Field::Username, Field::Password],
                valid_until: None,
            },
            [
                (
                    Field::Username,
                    SecretBytes::new("private+usér".as_bytes().to_vec()).unwrap(),
                ),
                (
                    Field::Password,
                    SecretBytes::new(b"p&ss=word%\"+ ".to_vec()).unwrap(),
                ),
            ]
            .into(),
        )
        .unwrap()
    }
    #[test]
    fn observation_removes_encoded_placeholders_before_password_resolution() {
        for encoding in [LoginEncoding::Form, LoginEncoding::Json] {
            let mut profile = profile(encoding);
            profile.csrf = Some(CsrfProfile {
                response_pointer: "/csrf".into(),
                submit_field: if encoding == LoginEncoding::Form {
                    "csrf"
                } else {
                    "/csrf"
                }
                .into(),
            });
            let values = Placeholders::new().unwrap();
            let (csrf, _) = CsrfToken::from_page(
                profile.csrf.as_ref().unwrap(),
                br#"{"csrf":"private-csrf"}"#,
            )
            .unwrap();
            let (media, body) = match encoding {
                LoginEncoding::Form => ("application/x-www-form-urlencoded", format!("user={}&password={}&csrf={}&keep=hello+world%26yes", values.username(), values.password(), csrf.placeholder()).replace("aap_", "%61ap_")),
                LoginEncoding::Json => ("application/json", serde_json::to_string(&json!({"credentials":{"user":values.username(),"password":values.password()},"csrf":csrf.placeholder(),"keep":[true,42,"hello world&yes"]})).unwrap().replace("aap_", "\\u0061ap_")),
            };
            let login =
                ValidatedLogin::parse(&profile, media, body.as_bytes(), &values, Some(&csrf))
                    .unwrap();
            let observation = login
                .observation()
                .expect("validated login must have a secret-free structural view");
            match encoding {
                LoginEncoding::Form => assert_eq!(observation.as_ref(), b"user=%5Bredacted%5D&password=%5Bredacted%5D&csrf=%5Bredacted%5D&keep=hello+world%26yes"),
                LoginEncoding::Json => assert_eq!(serde_json::from_slice::<Value>(&observation).unwrap(), json!({"credentials":{"user":"[redacted]","password":"[redacted]"},"csrf":"[redacted]","keep":[true,42,"hello world&yes"]})),
            }
            // Observation must not consume or alter the private substitution.
            let (private, _) = login.substitute(&snapshot()).unwrap();
            assert!(
                std::str::from_utf8(&private)
                    .unwrap()
                    .contains("private-csrf")
            );
        }
    }
    #[test]
    fn form_replaces_only_complete_fields_and_preserves_other_meaning() {
        let profile = profile(LoginEncoding::Form);
        let values = Placeholders::new().unwrap();
        let other = Placeholders::new().unwrap();
        assert_eq!(values.username().len(), 51);
        assert_eq!(values.password().len(), 51);
        assert_ne!(values.username()[8..], values.password()[8..]);
        assert_ne!(values.password(), other.password());
        let body = format!(
            "user={}&password={}&note=hello+world%26keep%3Dyes%25",
            values.username(),
            values.password()
        );
        for _ in 0..2 {
            let validated = ValidatedLogin::parse(
                &profile,
                "application/x-www-form-urlencoded",
                body.as_bytes(),
                &values,
                None,
            )
            .expect("valid form rejected");
            let (bytes, mut redactor) = validated.substitute(&snapshot()).unwrap();
            assert_eq!(
                std::str::from_utf8(&bytes).unwrap(),
                "user=private%2Bus%C3%A9r&password=p%26ss%3Dword%25%22%2B+&note=hello+world%26keep%3Dyes%25"
            );
            assert_eq!(
                redactor
                    .feed("private+usér / p&ss=word%\"+ ".as_bytes(), true)
                    .unwrap(),
                "[redacted] / [redacted]"
            );
        }
        assert!(
            ValidatedLogin::parse(
                &profile,
                "application/x-www-form-urlencoded",
                body.as_bytes(),
                &other,
                None
            )
            .is_err()
        );
    }
    #[test]
    fn json_selectors_and_csrf_rotate_without_revealing_values() {
        let values = Placeholders::new().unwrap();
        let mut profile = profile(LoginEncoding::Json);
        profile.fields.password = "/credentials/p~1ass~0word".into();
        profile.csrf = Some(CsrfProfile {
            response_pointer: "/meta/csrf".into(),
            submit_field: "/csrf".into(),
        });
        let csrf_profile = profile.csrf.as_ref().unwrap();
        let (token, page) = CsrfToken::from_page(
            csrf_profile,
            br#"{"meta":{"csrf":"private-csrf-token"},"title":"Login"}"#,
        )
        .expect("CSRF page refused");
        let page: Value = serde_json::from_slice(&page).unwrap();
        assert_eq!(page["meta"]["csrf"], token.placeholder());
        assert_eq!(page["title"], "Login");
        assert_eq!(token.placeholder().len(), 51);
        let body = serde_json::to_vec(&json!({"credentials":{"user":values.username(),"p/ass~word":values.password()},"csrf":token.placeholder(),"keep":[true,42,"ordinary"]})).unwrap();
        let (private, mut redactor) =
            ValidatedLogin::parse(&profile, "application/json", &body, &values, Some(&token))
                .unwrap()
                .substitute(&snapshot())
                .unwrap();
        let private: Value = serde_json::from_slice(&private).unwrap();
        assert_eq!(private["credentials"]["user"], "private+usér");
        assert_eq!(private["credentials"]["p/ass~word"], "p&ss=word%\"+ ");
        assert_eq!(private["csrf"], "private-csrf-token");
        assert_eq!(private["keep"], json!([true, 42, "ordinary"]));
        assert_eq!(
            redactor.feed(b"private-csrf-token", true).unwrap(),
            "[redacted]"
        );
        let (rotated, _) =
            CsrfToken::from_page(csrf_profile, br#"{"meta":{"csrf":"new-private-csrf"}}"#).unwrap();
        assert!(
            ValidatedLogin::parse(&profile, "application/json", &body, &values, Some(&rotated))
                .is_err()
        );
        assert!(ValidatedLogin::parse(&profile, "application/json", &body, &values, None).is_err());
        for page in [
            br#"{"meta":{"csrf":"a","csrf":"b"}}"#.as_slice(),
            br#"{"meta":{"csrf":false}}"#,
            br#"{}"#,
        ] {
            assert!(CsrfToken::from_page(csrf_profile, page).is_err());
        }
    }
    #[test]
    fn invalid_and_misplaced_placeholders_never_produce_a_validated_login() {
        let values = Placeholders::new().unwrap();
        let profile = profile(LoginEncoding::Form);
        let valid = format!("user={}&password={}", values.username(), values.password());
        assert!(
            ValidatedLogin::parse(
                &profile,
                "application/x-www-form-urlencoded",
                valid.as_bytes(),
                &values,
                None
            )
            .is_ok(),
            "valid control rejected"
        );
        for body in [
            format!("{valid}&password=other"),
            format!("{valid}&pass%77ord=other"),
            format!("{valid}&extra={}", values.password()),
            format!("{valid}&aap_pw1_unknown=ordinary"),
            format!("{valid}&note=prefixaap_un1_unknownsuffix"),
            format!("{valid}&note=%FF"),
            format!("{valid}&note=%0"),
            format!("{valid}&note=%xz"),
            format!("{valid}&note=x&note=y"),
            format!("{valid}&broken"),
            format!(
                "user={}&password=prefix{}",
                values.username(),
                values.password()
            ),
            format!("user={}&password=aap_pw1_invalid", values.username()),
        ] {
            assert!(
                ValidatedLogin::parse(
                    &profile,
                    "application/x-www-form-urlencoded",
                    body.as_bytes(),
                    &values,
                    None
                )
                .is_err(),
                "invalid form accepted: {body}"
            );
        }
        for media in [
            "application/json",
            "text/plain",
            "application/x-www-form-urlencoded;charset=latin1",
        ] {
            assert!(
                ValidatedLogin::parse(&profile, media, valid.as_bytes(), &values, None).is_err()
            );
        }
        assert!(
            ValidatedLogin::parse(
                &profile,
                "application/x-www-form-urlencoded",
                &vec![b'x'; 256 * 1024 + 1],
                &values,
                None
            )
            .is_err()
        );
    }
    #[test]
    fn json_duplicates_types_and_nested_placeholder_smuggling_are_rejected() {
        let values = Placeholders::new().unwrap();
        let profile = profile(LoginEncoding::Json);
        let base = json!({"credentials":{"user":values.username(),"password":values.password()},"untouched":true});
        assert!(
            ValidatedLogin::parse(
                &profile,
                "application/json",
                &serde_json::to_vec(&base).unwrap(),
                &values,
                None
            )
            .is_ok(),
            "valid JSON control rejected"
        );
        for extra in [
            json!({"nested":[values.password()]}),
            json!({"aap_cs1_unknown":"ordinary"}),
            json!({"nested":"prefix aap_pw1_unknown"}),
        ] {
            let mut candidate = base.clone();
            candidate["extra"] = extra;
            assert!(
                ValidatedLogin::parse(
                    &profile,
                    "application/json",
                    &serde_json::to_vec(&candidate).unwrap(),
                    &values,
                    None
                )
                .is_err()
            );
        }
        for value in [
            json!(null),
            json!(false),
            json!([values.password()]),
            json!(123),
            json!(format!("{}extra", values.password())),
        ] {
            let mut candidate = base.clone();
            candidate["credentials"]["password"] = value;
            assert!(
                ValidatedLogin::parse(
                    &profile,
                    "application/json",
                    &serde_json::to_vec(&candidate).unwrap(),
                    &values,
                    None
                )
                .is_err()
            );
        }
        let duplicate = format!(
            r#"{{"credentials":{{"user":"{}","password":"{}","pass\u0077ord":"{}"}}}}"#,
            values.username(),
            values.password(),
            values.password()
        );
        assert!(
            ValidatedLogin::parse(
                &profile,
                "application/json",
                duplicate.as_bytes(),
                &values,
                None
            )
            .is_err()
        );
    }
}
