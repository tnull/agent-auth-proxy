# Legacy authentication and credential injection

## Compatibility guarantee

Legacy mode lets an unchanged supported site receive its usual password and
cookies while the agent sees only fake credentials and sanitized responses.
It requires a site-specific resource profile and the
[password-manager interface](password-manager.md). It is not a new
authentication protocol between the daemon and that site.

A fake password is a one-use instruction to the daemon, not a password-derived
proof that the site can verify. The upstream password and cookies retain their
native replay properties. The proxy prevents their disclosure through managed
interfaces and restricts their use, but cannot make a stolen upstream cookie
one-use at an unchanged server.

## Issuance and binding

`vault.get_login` / logical `legacy.prepare` returns a password of this form:

```text
aap_lp1_<unpadded-base64url-of-32-random-bytes>
```

The complete value is 51 ASCII characters. If the username is private, issue
an independent 51-character `aap_lu1_` value too. Both map to one attempt and
expire together. Never derive the placeholder from the real password. A public
`sha256(URI || session_challenge)` construction adds no authentication by itself
and introduces representation ambiguity; explicit random handles with stored
bindings are the baseline.

The daemon records an attempt bound to tenant, agent session, item/account,
credential version, auth context, exact normalized HTTPS origin and login target
(including approved query), method, media type, credential field selectors,
grant, expiry, and state `issued`. The allowed lifetime is at most 120 seconds.
Possession of the fake password outside the bound session grants no authority.

Issuing another attempt does not increase the session's login budget. Allow
at most one active login exchange per auth context; parallel accounts or
isolated browser sessions need separate contexts. A new issuance explicitly
replaces and invalidates any previous unused attempt for that context.

## Submission rules

The baseline supports `POST` with either:

- `application/x-www-form-urlencoded`, decoded exactly once using UTF-8 form
  rules. A selector is one exact decoded field name.
- `application/json` with UTF-8 encoding. A selector is an exact JSON Pointer
  identifying a string value. Duplicate JSON member names are rejected.

The profile selects one format and declares any permitted media-type parameters.
Unsupported content encodings, multipart bodies, client-side password hashing,
encrypted login payloads, and arbitrary script-generated authentication need
separate reviewed adapters. The daemon does not search opaque bytes for strings.

Before releasing credentials, the daemon MUST:

1. Authenticate the local session and resolve the granted item/context.
2. Validate the precise target, method, profile, content type, body limits, and
   current destination. Reject agent-supplied authentication headers/cookies
   on daemon-managed routes.
3. Parse the complete bounded body. Require exactly one designated password
   field containing the whole issued fake password. If username substitution
   is required, require its bound fake value in the designated field as well.
   If the username is visible, require the item-selected value.
4. Reject duplicate credential fields, type mismatches, substrings, malformed
   encodings, and recognized credential placeholders in any other field,
   header, or URI. An invalid/expired placeholder is never forwarded as a
   literal password. The reserved `aap_lp1_` / `aap_lu1_` namespaces may only
   appear in their approved substitution locations on these routes.
5. Bind/validate CSRF and pre-login state according to the profile. Authorize
   the final operation and approval, if required. Recheck store availability,
   credential version, grant validity, and session lifetime.
6. Atomically move the attempt from `issued` to `consumed` before any real
   credential bytes leave the daemon. Replace only those parsed values with
   the pinned real values, re-encode correctly, recompute framing, and send
   over verified TLS to the exact admitted endpoint.

Failed local validation releases no credential. Once consumed, the attempt
never becomes usable again, including after authentication failure, connection
loss, or a lost response. A site login failure is not a reason to try another
stored password or account automatically.

This mode permits form serialization changes but preserves the meaning of
unmodified fields. Byte-signed forms, unsupported character sets, or ambiguous
parsers require a specific adapter or rejection. No password substitution is
allowed in a GET query, URL userinfo, arbitrary message text, logs, or uploads.

## Private cookie sessions

A typical agent flow is: search the site with `vault.search_items`, select an
item with `vault.get_login`, fetch the login page using the returned auth context,
then submit the returned fake values to the declared action. The page fetch lets
the daemon capture pre-login cookies and profiled CSRF state. Subsequent protected
requests select the same context; the daemon supplies its private cookies.
The agent never has to copy a real cookie out of a login response.

The daemon owns the cookie jar before login as well as after it. Partition by
tenant, local session, resource profile, account, and auth context. Never share
a jar merely because two requests use the same hostname or stored password.

Consume each `Set-Cookie` separately and remove it from the agent response on
all profiled routes, not only the successful login response. This includes
redirects, errors, cookie refreshes, deletion, and logout. The conservative
baseline keeps all cookies private; no authentication cookie or fake upstream
authentication cookie is placed in the agent's jar.

Use cookie domain, path, expiry, and secure-transport rules for upstream
selection. Honor replacement/deletion and do not split a cookie header on commas.
The proxy additionally intersects selection with exact enrolled origins, ports,
and routes; a broad cookie Domain cannot grant another destination. Reject
public-suffix domain cookies and invalid cookie attributes.
[RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html)

Cookies marked Secure never travel without verified TLS. Keep HttpOnly cookies
private, and do not treat cookies lacking HttpOnly as safe to expose. Apply
SameSite and cookie-prefix requirements for the supported client profile.
Without trustworthy browser/site-navigation context, use the enrolled login
flow and conservative same-site requests; do not infer cross-site consent from
agent-controlled `Origin` or `Referer` headers. Browser partitioned cookies and
complex cross-site federation require an explicit later compatibility profile.

Strip incoming agent Cookie fields on a managed route and construct the outbound
Cookie field exclusively from the selected jar. Rotation on a response takes
effect before forwarding that response. Serialize cookie-mutating exchanges
per context in the baseline to avoid racing login/refresh/logout updates;
applications needing parallel session mutations need a reviewed conflict policy.

The common local `auth_context` associates follow-up requests with the jar.
A transparent session with one enrolled account can infer this association.
If an application requires JavaScript to read cookies or tokens, hiding all
cookies may break it: explicitly support safe, profiled virtualization or
declare the application unsupported. Do not solve it by revealing real cookies.

## CSRF, redirects, and response secrets

CSRF is separate from authentication. The profile declares token acquisition,
storage, expected login action, and exact request/response locations. Pre-login
cookies remain private. A declared noncredential CSRF field may be exposed if
the profile permits; a value equal to a secret cookie or otherwise usable as a
credential must remain private and be replaced with a session-bound placeholder.
CSRF placeholders use `aap_lc1_` plus 32 random bytes in base64url, are bound to
the attempt and field, and are consumed together with it. A generic HTML/script
rewriter is not assumed.

Redirect handling is profile-defined. Check every hop's scheme, origin, method,
target, selected jar, and policy. Never carry a substituted password body through
a 307/308 automatically; require a separately enrolled action and new authorized
attempt. An enrolled successful login may follow a 303 or profiled 302 with GET
and no credential body. Cross-origin SSO requires an explicitly enrolled chain,
separate origin-specific credentials/jars, and consent where applicable.

Capture private cookies before processing the redirect. Scrub authentication
material from Location fields, bodies, trailers, and any declared token fields
before returning them. Error pages can echo submitted passwords; profiled login
responses must be bounded and checked before delivery. A route that cannot
safely interpret a secret-bearing response must withhold it and return a safe
error, not pass it through untouched.

Successful login requires the profile's declared success evidence, not merely
HTTP 200 or receipt of any cookie. Subsequent 401/403 or application login-page
signals update context state according to that profile. Do not automatically
repeat an unsafe action after reauthentication. Failed login leaves no
authenticated context and invalidates its tentative authentication state.

Exact-value and known-encoding secret suppression is defense in depth; it cannot
detect every transformation a malicious resource could use to echo a secret.
Credential isolation is guaranteed for the supported authentication surfaces,
with trusted credential recipients, not for arbitrary malicious content.

## Logout, expiry, and recovery

Local logout immediately revokes the context and its placeholders and prevents
any further jar use. An enrolled remote logout operation may use a detached
private copy of the jar solely for that operation, after which it is discarded.
Record remote outcome separately. Operator revocation removes the ability to
log in again; simple logout alone does not remove a standing login grant.

Context expiry, session termination, and credential/store revocation invalidate
local cookie authority. A daemon restart drops baseline jars and pending
attempts; persistent session recovery is a future opt-in profile. Never revive
an old fake password or silently attach another session's cookies.

## Existing API keys, OAuth, and MCP authentication

For a model provider or other fixed API profile, resolve the permitted secret
item and insert its required header at final dispatch. The agent may use a
documented inert SDK placeholder, but it does not select the real key or bypass
session authentication. Remove conflicting caller credentials and forbid
credential-bearing URLs. Providers and endpoints are chosen by policy.

OAuth access and refresh tokens remain in the daemon. Bind acquired authority
to the upstream audience, account, and local grant; handle refresh through
approved endpoints outside the sandbox. A remote MCP server receives its own
upstream token, never the incoming local token. Standard OAuth browser/device
interaction must use the future trusted user channel, not expose refresh tokens
or approval authority in model context.
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)

These are explicit compatibility profiles with weaker upstream replay
guarantees than `AAP-CR/1`. A failed signature challenge never activates them.

## Acceptance scenarios

- Site/item MCP discovery and fake username/password submission produce a
  successful login with all actual secrets confined to daemon/store/upstream.
- The same fake password fails on a second use, another session/account/origin,
  altered action/query, or a different body field. Parallel redemption has one
  winner and sends one real credential-bearing request.
- Duplicate fields, nested JSON ambiguity, malicious form actions, unexpected
  encodings, and placeholder substrings do not cause substitution or forwarding.
- Pre-login CSRF, Set-Cookie on error/redirect, rotation, deletion, account
  switching, and logout use the correct private jar without exposing secrets.
- A 307 to another site never forwards the password; a permitted post-login GET
  transition gets only its own authorized cookies.
- Lost login responses, invalid credentials, locked stores, password rotation,
  restart, and interrupted observation do not resurrect one-use attempts.
- Password echoes and declared body tokens are withheld/redacted; unsupported
  script authentication returns an explicit compatibility error.
