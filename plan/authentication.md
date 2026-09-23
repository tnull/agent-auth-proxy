# Authentication and credential injection

## Credential isolation guarantee

The proxy lets an unchanged supported site receive its usual password and
cookies while the agent sees only fake credentials and sanitized responses.
It requires a site-specific resource profile and the
[password-manager interface](password-manager.md). The daemon uses the site's
existing authentication protocol.

A fake password identifies a credential substitution within an authenticated
proxy context. It is reusable within that context until expiry or revocation;
possession alone does not authorize a login. The upstream password and cookies
retain their native properties. The proxy prevents their disclosure through
managed interfaces and restricts their use. Duplicate business actions remain
subject to authorization and application idempotency, independently of whether
the agent knows a real credential.

## Issuance and binding

`vault.get_login` / logical `auth.prepare` returns a password of this form:

```text
aap_pw1_<unpadded-base64url-of-32-random-bytes>
```

The complete value is 51 ASCII characters. If the username is private, issue
an independent 51-character `aap_un1_` value too. Both map to the same credential
binding and expire together. Never derive a placeholder from the real password;
use random opaque values with explicit stored bindings.

The daemon records a placeholder binding to tenant, agent session, item/account,
credential version, auth context, exact normalized HTTPS origin and login target
(including approved query), method, media type, credential field selectors,
grant, expiry, and state `active`. Lifetime is finite, selected by operator
policy, and capped by context, session, and grant expiry. A binding becomes
`expired` or `revoked`; successful substitution does not consume it. Possession
of the fake password outside the bound session grants no authority.

Issuance or reuse does not increase the session's login budget. Each submission
requires its own authorization and quota check. Allow at most one active login
exchange per auth context; reject a concurrent exchange with `auth_in_progress`.
Parallel accounts or isolated browser sessions need separate contexts. A new
issuance for an existing context replaces and revokes its previous placeholders.

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
   literal password. The reserved `aap_pw1_` / `aap_un1_` namespaces may only
   appear in their approved substitution locations on these routes.
5. Bind/validate CSRF and pre-login state according to the profile. Authorize
   the final operation and approval, if required. Recheck store availability,
   credential version, grant validity, and session lifetime.
6. Admit the login operation with current context validity, concurrency, and
   budget checks before any real credential bytes leave the daemon. Replace
   only the designated parsed values with the pinned real values, re-encode
   correctly, recompute framing, and send over verified TLS to the exact
   admitted endpoint. Do not consume the credential placeholders.

Failed local validation releases no credential. Reusing a valid placeholder
requires a new authorized login operation and does not make an uncertain earlier
submission safe to retry. The common request-ID contract prevents duplicate
dispatch for the same operation. A site login failure is not a reason to try
another stored password or account automatically. Apply attempt limits to
failed logins as well as successful ones.

Form substitution permits serialization changes but preserves the meaning of
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
Cookie field exclusively from the selected jar. Capture cookie changes and
prepare redaction before releasing affected response content, but keep those
changes provisional for the current exchange. Publish the updated jar and CSRF
state for subsequent operations only at the engine's successful
[completion boundary](lifecycle.md#completion-and-private-state-publication).
Receipt of Set-Cookie or a successful HTTP status alone does not publish login
success. Serialize cookie-mutating exchanges per context through completion or
abandonment; applications needing parallel session mutations need a reviewed
conflict policy.

If validation, required observation, cancellation, or authority revalidation
prevents completion, discard tentative cookies/CSRF and invalidate the affected
context conservatively. Do not restore an earlier jar as a claimed rollback of
upstream cookie refresh, deletion, or login. Subsequent use requires fresh,
explicitly authorized preparation, not an automatic repeated login. Local
logout/revocation still takes effect immediately, even if recording fails.

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
CSRF placeholders use `aap_cs1_` plus 32 random bytes in base64url and are bound
to the context, form target, field, and current upstream CSRF value. Their
lifetime and permitted use follow that site's CSRF rules; rotation invalidates
the old mapping. Reusable password placeholders never bypass CSRF validation.
A generic HTML/script rewriter is not assumed.

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
local cookie authority and credential placeholders. A daemon restart drops
baseline jars, placeholder bindings, and pending login operations; persistent
session recovery is a future opt-in profile. Never revive an expired/revoked
fake password or silently attach another session's cookies.

## API keys, OAuth, and MCP authentication

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

Each mechanism is selected by an approved resource profile. Authentication
failures never select a different credential or expand the permitted scope.

## Acceptance scenarios

- Site/item MCP discovery and fake username/password submission produce a
  successful login with all actual secrets confined to daemon/store/upstream.
- A valid fake password can be reused for a separately authorized login within
  its bound context. It fails in another session/account/origin, with an altered
  action/query or field, or after expiry, revocation, or credential rotation.
- Duplicate request IDs never dispatch the same login twice. Concurrent login
  exchanges cannot race the context's cookies or bypass attempt limits.
- Duplicate fields, nested JSON ambiguity, malicious form actions, unexpected
  encodings, and placeholder substrings do not cause substitution or forwarding.
- Pre-login CSRF, Set-Cookie on error/redirect, rotation, deletion, account
  switching, and logout use the correct private jar without exposing secrets.
- A 307 to another site never forwards the password; a permitted post-login GET
  transition gets only its own authorized cookies.
- Lost login responses, invalid credentials, locked stores, password rotation,
  restart, and interrupted observation do not revive invalidated bindings or
  trigger automatic retries after uncertain dispatch.
- Completion races leave provisional cookie/CSRF state unusable after
  retirement; an independent successful exchange commits it only with coherent
  operation and required-observation endings. Apply the
  [L6 acceptance cases](lifecycle.md#l6-completion-acceptance-cases).
- Password echoes and declared body tokens are withheld/redacted; unsupported
  script authentication returns an explicit compatibility error.
