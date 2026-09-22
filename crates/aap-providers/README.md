# aap-providers

Strict, credential-free request inspection for the first text-only provider
fixtures. The broker supplies this inspector before retrieving API keys.
Only explicitly supported fields are accepted: model, string-content messages,
stream, output-token bounds, temperature, and Anthropic's string system prompt.
Images, remote resource inputs, hosted tools, unknown fields, and duplicate JSON
members are rejected. This is deliberately a subset, not general API conformance
or a provider SDK. No network or credential-store dependencies are present.

The trusted profile still owns destination, routes, header policy, and limits.
The generic profile is for explicitly enrolled non-provider resources; operators
must not use it to bypass model-provider feature inspection.

The selected fixture request fields follow the official
[chat-completion reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
and [messages reference](https://platform.claude.com/docs/en/api/messages/create).
Our positive output-token limit and message-count limits are stricter local
policy, not claims about every provider/model's accepted range. Live service
compatibility and additional tool/content schemas remain separate checks.
