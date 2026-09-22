//! Narrow supported provider schemas, checked before credential access.

use aap_types::{
    ErrorCode, Result,
    profile::{ProviderKind, RequestInspector},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: String,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    model: String,
    messages: Vec<Message>,
    #[serde(default, rename = "stream")]
    _stream: bool,
    max_tokens: Option<u32>,
    max_completion_tokens: Option<u32>,
    temperature: Option<f64>,
    system: Option<String>,
}

pub struct TextOnly;
impl RequestInspector for TextOnly {
    fn inspect(&self, provider: ProviderKind, body: &[u8]) -> Result<()> {
        if body.len() > 1024 * 1024 {
            return Err(ErrorCode::LimitExceeded.into());
        }
        if provider == ProviderKind::Generic {
            return Ok(());
        }
        let request: Request =
            aap_types::json::decode(body).map_err(|_| ErrorCode::InspectionUnavailable)?;
        let anthropic = provider == ProviderKind::AnthropicMessages;
        if request.model.is_empty()
            || request.model.len() > 128
            || !request.model.is_ascii()
            || request.model.bytes().any(|b| b <= b' ' || b == 127)
            || request.messages.is_empty()
            || request.messages.len() > 256
            || request.messages.iter().any(|message| {
                !if anthropic {
                    matches!(message.role.as_str(), "user" | "assistant")
                } else {
                    matches!(
                        message.role.as_str(),
                        "user" | "assistant" | "system" | "developer"
                    )
                }
            })
            || request
                .messages
                .iter()
                .map(|message| message.content.len())
                .sum::<usize>()
                > 1024 * 1024
            || request
                .max_tokens
                .is_some_and(|limit| limit == 0 || limit > 1_000_000)
            || request
                .max_completion_tokens
                .is_some_and(|limit| limit == 0 || limit > 1_000_000)
            || (request.max_tokens.is_some() && request.max_completion_tokens.is_some())
            || (anthropic
                && (request.max_tokens.is_none() || request.max_completion_tokens.is_some()))
            || (!anthropic && request.system.is_some())
            || request
                .system
                .as_ref()
                .is_some_and(|system| system.len() > 131_072)
            || request.temperature.is_some_and(|value| {
                !value.is_finite() || value < 0.0 || value > if anthropic { 1.0 } else { 2.0 }
            })
        {
            return Err(ErrorCode::InspectionUnavailable.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn supports_bounded_text_messages_for_both_providers() {
        for (provider, body) in [
            (
                ProviderKind::OpenAiChat,
                json!({"model":"fixture-model","messages":[{"role":"user","content":"hello"}],"stream":true,"max_completion_tokens":32}),
            ),
            (
                ProviderKind::AnthropicMessages,
                json!({"model":"fixture-model","messages":[{"role":"user","content":"hello"}],"max_tokens":32,"system":"be concise","stream":false}),
            ),
        ] {
            TextOnly
                .inspect(provider, &serde_json::to_vec(&body).unwrap())
                .expect("supported text schema refused");
        }
    }
    #[test]
    fn network_features_unknown_fields_and_duplicate_members_fail_closed() {
        let valid = json!({"model":"fixture-model","messages":[{"role":"user","content":"hello"}]});
        assert!(
            TextOnly
                .inspect(
                    ProviderKind::OpenAiChat,
                    &serde_json::to_vec(&valid).unwrap()
                )
                .is_ok()
        );
        for (field, value) in [
            ("tools", json!([{"type":"web_search"}])),
            ("metadata", json!({})),
            (
                "messages",
                json!([{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://unadmitted.test"}}]}]),
            ),
            ("messages", json!([])),
        ] {
            let mut body = valid.clone();
            body[field] = value;
            assert!(
                TextOnly
                    .inspect(
                        ProviderKind::OpenAiChat,
                        &serde_json::to_vec(&body).unwrap()
                    )
                    .is_err()
            );
        }
        assert!(
            TextOnly
                .inspect(
                    ProviderKind::OpenAiChat,
                    br#"{"model":"x","model":"y","messages":[]}"#
                )
                .is_err()
        );
        assert!(
            TextOnly
                .inspect(
                    ProviderKind::AnthropicMessages,
                    &serde_json::to_vec(&valid).unwrap()
                )
                .is_err()
        );
    }
}
