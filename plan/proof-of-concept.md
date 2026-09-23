# First proof-of-concept scope

This is the proposed acceptance baseline for the implementation work packages,
not a report that the capabilities already work. Track actual evidence in
[the delivery tracker](../docs/proof-of-concept.md). Keep the existing project
and crate names until a separate rename decision.

## Supported demonstration

Demonstrate a real standalone daemon on Linux, outside a confined agent process,
with SQLCipher credential custody and two isolated agent sessions. Use synthetic
credentials, local controlled HTTPS origins, and an independently connected
observation consumer. No personal Keychain, paid model request, or production
account is necessary to establish the core behavior.

| Surface | Required first proof | Explicitly not claimed by that proof |
| --- | --- | --- |
| Provider brokerage | OpenAI-style chat-completion and Anthropic-style messages fixtures; final key injection, bounded streaming, cancellation | Every provider endpoint/model/tool, or live-provider conformance without separate verification |
| Password manager | MCP item lookup, fake username/password issuance, status, logout, account/session separation | Agent access to native store enumeration, real passwords, or item administration |
| Website authentication | Controlled site with form-encoded POST and a JSON variant, private pre-login/auth cookies, profiled CSRF and explicit application success evidence | Universal website compatibility, arbitrary HTML/script rewriting, cross-origin SSO |
| TLS proxy | Admitted CONNECT, scoped local CA, inspected HTTP/1.1, independently verified upstream TLS | Certificate-pinning bypass, application-layer decryption, HTTP/2 or HTTP/3 support before their suites exist |
| MCP mediation | Session-bound local tools/stdio bridge and one pinned remote HTTP transport; messages use the same engine path | Unrestricted server-initiated sampling, elicitation, or a remote server's unseen egress |
| TCP | Explicitly enrolled plaintext fixture, bounded duplex relay and directional observation | Generic secret injection, implicit opaque encrypted bypass, UDP/QUIC |
| Observation | Redacted content/lifecycle events, bounded retention, gaps/resume, best-effort and required recording behavior | IDS algorithms, raw-secret packet capture, infinite retention or exactly-once delivery |
| Human approval | Asynchronous trusted extension, fake-provider conformance tests, fail-closed unconfigured behavior | Production push UI, signed-response protocol, or upstream OTP automation |
| Reuse | External Rust consumer and trusted embedding example using the same operation semantics | A completed Goose integration or safety when embedded in an untrusted agent |

Provider fixtures exercise their selected request/response schemas; they do
not imply a supported live account. Reject undeclared network-capable provider
features, including hosted fetch/search tools or remote resource inputs, before
credential resolution. Local tool-call descriptions do not by themselves execute
network work, but each subsequent local tool request still needs admission.

For the first site, prefer explicit JSON login metadata and success fields even
when the submitted credentials use form encoding. This permits precise CSRF
and response-secret handling without introducing a browser/HTML engine. An
actual site's HTML profile needs its own reviewed compatibility tests before
it is advertised. Redirect handling is deny-by-default; separately prove a
declared same-origin post-login GET transition and rejection of 307/308 password
re-forwarding. No HTTP library follows redirects implicitly.

The controlled cookie fixture starts with host-only Secure cookies and
same-origin requests. Any Domain, SameSite=None, Partitioned, or unknown cookie
extension is unsupported. Support broader cookie domains only with reviewed
domain/public-suffix behavior; rejecting all Domain attributes is intentional
for this first profile. Cookies without HttpOnly remain equally private.

The [local MCP contract](mcp.md) pins version `2025-11-25`, its seven tools,
bounded result envelopes, and credential-free bridge behavior. The separate
[remote MCP contract](remote-mcp.md) pins upstream Streamable HTTP to the same
version, with private session state and enrolled tools. Prove both JSON and SSE
responses; record its deliberately narrower capability and reconnect limits
in fixture and operator docs. Unsupported server operations fail explicitly.
The mediated server fixture performs only declared local operations; do not
infer visibility into arbitrary remote egress.

The [TCP relay contract](tcp.md) narrows the byte-stream fixture to an explicitly
enrolled credential-free service. Its duplex/half-close, shared capacity,
approval, and observation acceptance checks are W7 gates. An arbitrary raw
channel does not prove plaintext inspection or per-action authorization.
The proposed [local wire binding](tcp-binding.md) adds strict HTTP upgrade and
binary-frame fixtures, explicit terminal delivery, and reserved control capacity;
it is not an implemented endpoint until the daemon/client checks pass.

## Initial finite limits

Use explicit limits from the first integrated tests. The following are proposed
starting defaults, not production sizing claims. Operator configuration may
tune them; session and route limits can only narrow the operator ceilings.
Zero must not mean unlimited, and chunking cannot bypass total-byte limits.

| Budget | Starting value |
| --- | --- |
| Session lifetime | 60 minutes |
| Placeholder/context lifetime | 10 minutes, capped by session and grant expiry |
| Retained authentication contexts | 16 per session and 64 per broker, including terminal tombstones until session teardown |
| Discovery pagination | 50 records per page; at most 64 session/query-bound cursors per session |
| Tracked operation IDs per session | 4,096; reject new operations when exhausted |
| Operation tracking and retained result state | 8 MiB per session and 64 MiB globally; retain dispatch/uniqueness state rather than silently forgetting IDs |
| Active upstream operations per session | 8 |
| Pending approvals per session | 16, with at most 4 MiB total retained request data |
| Approval wait | 5 minutes, capped by all relevant lifetimes |
| Login attempts | 5 per item/session and 20 per item/broker per 10 minutes; fresh contexts do not reset the counters |
| Buffered authentication request or response | 256 KiB each |
| General request body | 1 MiB, unless an explicit supported streaming-upload profile exists |
| Ordinary streamed response or TCP direction | 32 MiB total; bounded incremental buffers |
| Upstream connection establishment | 10 seconds |
| HTTP stream inactivity / total operation duration | 60 seconds / 10 minutes |
| TCP phase deadlines | 10-second local handshake, up to 5-minute approval, 10-second preparation/dial, up to 10-minute connected lifetime, 2-second terminal delivery; always capped by authority expiry |
| Catalog input | 1 MiB and 1,000 enrolled items |
| Observation retained content | 8 MiB per session and 64 MiB globally; bounded event count as well |

Limit checks cover encoded and decoded data where relevant, headers, nesting,
cookie counts/sizes, certificate caches, and global session/listener counts.
Record remaining precise parser/connection defaults with the owning adapter;
no unbounded collection may hide behind an unspecified default. Exceeding a
bound yields a safe error or explicit incomplete stream, never silent success.

## Delivery order and demonstration gates

1. **Policy and custody (W0–W2):** strict wire contracts, validated catalog,
   configuration privacy, restrictive approval composition, session/deduplication
   lifecycle, store conformance, and actual SQLCipher encryption. No external
   secret use until these checks pass.
2. **Provider vertical slice (W3–W4):** one fixture end to end through the
   daemon, then a second profile; private per-session/operator sockets, safe
   streams, cancellation, restart invalidation, baseline observation, and the
   first actual-sandbox [confinement proof](deployment.md).
3. **Password-manager vertical slice (W5–W6):** MCP search through fake form
   submission to protected resource access; repeat with the JSON variant and
   with a second isolated session. Prove logout, rotation, store lock/outage,
   CSRF rotation, cookie refresh/deletion, and no password/cookie echoes.
4. **Coverage and reuse (W7–W8):** real remote MCP mediation and TCP fixture,
   external observation subscriber, overload/gap/required-mode tests, reusable
   embedding/client example, and confinement-suite reruns for all added adapters.
   Apply the [reuse acceptance matrix](reuse.md#shared-behavioral-suite) to both
   the embedded and daemon paths; check independent consumer dependency closures.
5. **Native custody (W9):** implement the isolated macOS adapter where feasible;
   list native access, signing, lock, and existing-item tests requiring macOS.
   A Linux test pass never establishes Keychain runtime compatibility.

No fixed calendar estimates are implied; each gate needs executable evidence.
Test uncertain delivery with a server that records reception and then drops
the connection. Assert that the daemon reports uncertainty without dispatching
again, rather than treating a transport exception as proof of non-execution.

The [confinement suite](deployment.md#confinement-acceptance-suite) attempts
direct IPv4, IPv6, DNS, alternate sockets, host filesystem/control/process access,
descendant escape, and inherited-descriptor escape from the actual sandbox.
Use live positive controls so absent services cannot produce false passes.
If the test host lacks the necessary isolation facilities, report
that release gate as unverified; a skipped test is not a pass. Proxy-only tests
still establish narrower behavior but cannot establish complete interception.

## Handoff and deferred decisions

The handoff includes exact supported profiles/transports, runnable synthetic
demonstrations, format/build/test results, dependency-boundary checks, operator
setup/recovery instructions, and an explicit list of unverified claims.
Apply the [operator lifecycle acceptance gates](operations.md#acceptance-and-delivery)
to the custody and recovery portions of that handoff; do not equate a low-level
backup function with a verified end-to-end restore workflow.
Remaining choices should not be answered by weakening the security contract:

- Product naming and distribution license before publishing.
- First real provider accounts and website profiles before production enrollment.
- Production sandbox packaging and supported deployment platforms.
- Real-content observation retention and collector access policy.
- Human-approval UI, signer trust, and native unlock experience.
- macOS runtime evidence before advertising a macOS release.

Publishing crates, installing a system-wide CA, contacting real services with
stored credentials, and modifying Goose/Loupe are not implied by this proof.
