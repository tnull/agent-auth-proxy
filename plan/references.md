# Sources, alternatives, and Loupe findings

Research date: 2026-09-22. Sources distinguish published specifications,
changing drafts, local evidence, and project proposals.

## Standards assessment

| Source | Contribution / decision |
| --- | --- |
| [AAuth overview](https://www.aauth.dev/) | Candidate ecosystem for identity/delegation; use a pinned draft for wire requirements |
| [AAuth revision 10](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-10) | Individual Internet-Draft dated 2026-08-06, not an adopted standard |
| [AAuth section 12.8.4.2](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-10#section-12.8.4.2) | Optional within-window replay caching does not establish mandatory one-use challenges |
| [HTTP Message Signatures, RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) | Standard signature serialization and component coverage; application requirements remain necessary |
| [Digest Fields, RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) | Standard content-byte digest field |
| [DPoP, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | Sender-constrained OAuth option with different request-binding properties |
| [OAuth security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Security reference for compatibility token acquisition/refresh |
| [Cookies, RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html) | Base cookie semantics; additional browser behavior needs explicit profiles |
| [HTTP early data, RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html) | Replay concerns support disabling early data on authenticated paths |
| [MCP authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Separate local authorization and upstream OAuth audience/token handling |
| [MCP security practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Confused-deputy and token-passthrough concerns |

Pin draft revisions for interoperability claims and review upgrades explicitly.
The `AAP-CR/1` nonce endpoint, enrollment assumptions, state machine, limits,
custom headers, and MCP vault schemas are project proposals; the RFCs do not
standardize them. Choosing strict signatures is a design inference from the
requested one-use, query/body-bound behavior, not a claim that AAuth or DPoP is
unsuitable generally.

## Local Loupe baseline

Inspected `../loupe` at commit
`7261a264aaa819ebc4c505b7c6e8f400119f60a4`. Its unrelated untracked user files
were not changed. Findings come from tracked source/history; its tests were
not executed for this planning task.

| Evidence | Relevant behavior |
| --- | --- |
| [`model_proxy.rs`](../../loupe/crates/loupe-worker/src/llm/model_proxy.rs) | Credential-free loopback adapter relays to the job's host broker socket |
| [`model_broker.rs`](../../loupe/crates/loupe-worker/src/llm/model_broker.rs) | Host-owned upstream/credential/model policy, limits, injection, streaming |
| [Broker integration tests](../../loupe/crates/loupe-worker/tests/model_broker.rs) | Sandbox and CLI-to-broker contract scenarios; source evidence only |
| [Loupe README](../../loupe/README.md) | Provider-key isolation and current sandbox egress behavior |
| [`988526c`](https://github.com/project-loupe/loupe/commit/988526c) | Introduces the credential-free broker core |
| [`9590ee6`](https://github.com/project-loupe/loupe/commit/9590ee6) | Isolation gates, bounded connections, upstream redirect rejection |
| [`b2221cc`](https://github.com/project-loupe/loupe/commit/b2221cc) | Rejects `mcp_servers`, which can make the provider contact caller-chosen URLs |

Transfer host-selected authority, per-job ingress binding, absence of secrets
in the sandbox adapter, removal of caller authentication, final credential
insertion, bounded streams, and refusal of credential-bearing redirects.

The `mcp_servers` correction shows that delegated external communication can
appear outside an obvious tool list. This daemon needs semantic policy for all
such features. A denylist of known fields also needs a strategy for newly
introduced provider capabilities; full-coverage profiles should allow only
understood network-capable features.

Scope differences from the inspected Loupe implementation:

- The broker covers a small provider surface, not general TLS interception,
  secret-store-backed password management, or cookie virtualization.
- Its response-header sanitizer removes framing/hop-by-hop fields; it is not
  the private Set-Cookie capture and secret-response filtering required here.
- Its documented default permits public IPv4 egress. Complete interception in
  this plan requires all sandbox egress to use the mediator instead.
- It does not implement this plan's resource nonce verifier or observation
  export contract.

These are source-based scope differences, not claims of newly demonstrated
vulnerabilities in Loupe's intended deployment.
