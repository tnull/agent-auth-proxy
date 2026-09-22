# aap-auth

Private authentication transforms, independent of destination selection and
network sockets. The first implemented path prepares an API-key header from a
coherent store snapshot, injects it only into the broker's private request, and
sanitizes supported response streams. Prepared secrets have no debug or
serialization implementation. The engine remains responsible for admission,
approval, store revalidation, and operation lifecycle.

Known-value suppression is defense in depth, not protection against a malicious
upstream deliberately encoding or fragmenting secrets into covert channels.
Supported body views are uncompressed JSON, event streams, and plain text;
other encodings fail closed. Response headers are reconstructed from safe
constants; authentication cookies, trailers, redirects, and stale lengths are
not exposed by this initial API-key path. New Set-Cookie
values are captured for echo suppression, but this API-key path does not retain
or send them on subsequent requests.

## Website transformation primitives

`login::Placeholders` independently generates opaque username/password values.
`ValidatedLogin::parse` requires exact whole values in the configured form fields
or JSON pointers before a snapshot is supplied. It rejects duplicate fields,
invalid UTF-8/percent escapes, non-string credentials, misplaced reserved
placeholders, unsupported media types, and bodies over 256 KiB. Form input has
at most 128 unique fields; serialization preserves unmodified field meaning,
not original bytes. JSON uses strict duplicate-member parsing. Both the input
and substituted output are size-checked.

`CsrfToken` virtualizes one declared string in a bounded JSON login-page body.
Replacing that token invalidates the previous placeholder. Other page fields
still require response sanitization; this is not an HTML/browser rewriter.
Substitution returns private upstream bytes and a redactor for the resolved
username, password, and CSRF value. Visible usernames are currently unsupported:
that path needs explicit approved disclosure, not a silent password-store read.

`cookies::CookieJar` captures each Set-Cookie header separately and removes all
cookie-setting headers before return, including on error. It is bound to an
exact HTTPS origin **including port**; the engine must additionally partition
by session/account/context and authorize every route. Supported cookies are
host-only, Secure, optionally HttpOnly, with absent/Strict/Lax SameSite. Domain,
SameSite=None, Partitioned, quoted values, duplicate attributes, duplicate
same-name/path assignments in one response, and unknown extensions fail closed.
No public-suffix dependency is needed because every Domain attribute is refused.

Path selection/defaults, refresh, expiry, Max-Age precedence, deletion, and
case-insensitive `__Host-` constraints are checked. There are at most eight
cookies, eight setting headers per response, 4 KiB per setting header, a 32 KiB
outgoing Cookie header, and sixteen historical values for echo suppression.
History includes replaced/deleted values until context revocation; exhaustion
fails rather than forgetting secrets. Rejected captures clear the entire jar;
the engine must withhold that response and invalidate its context. Outgoing
cookie headers are sensitive and private. No jar has Debug/Serialize support.

These deliberately narrow fixture rules are informed by
[RFC 6265](https://www.rfc-editor.org/rfc/rfc6265) and the
[HTTP working-group cookie draft](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html),
reviewed 2026-09-22. They do not claim general browser conformance.

Eight unit tests cover positive transformations and malicious/ambiguous inputs.
All initially failed against stubs. A further test covers bounded merging of
private redaction templates without carrying buffered stream content forward.
**Engine context lifecycle, store-version revalidation, action approval, login
success evaluation, redirect policy, MCP, and TLS interception are not supplied
by these primitives.** In particular,
neither a placeholder nor a CookieJar grants authority to dispatch a request.
The [engine](../aap-engine/README.md) now integrates them for the controlled
website profile exposed through the daemon's explicit local operation API.

`sanitize_login_redirect` is an opt-in response transform for a 303 and an exact
already-authorized HTTPS target. It reconstructs only the canonical Location,
checks it against both existing secrets and newly captured cookie values, and
sanitizes the response body. Other statuses/locations fail; the ordinary
`sanitize_response` path still rejects every redirect. The helper neither
decides login success nor follows the Location. An additional test covers this
narrow transform and confirms the default path remains redirect-denying.
