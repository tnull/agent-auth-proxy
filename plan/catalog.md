# Catalog format and lifecycle

Status: proposed version-1 contract, not a claim that the current draft Rust
types implement all validation. The catalog is private configuration, not a
secret store or an agent-facing API.

## File boundary

Use UTF-8 JSON in `catalog.json`, with no comments, includes, environment
substitution, or executable expressions. The existing JSON dependency is
sufficient; no additional configuration language or database is needed.
Reject duplicate members at every depth, unknown members, unsupported schema
versions, invalid references, and inputs exceeding configured finite limits.

The catalog contains enrolled items and their item-level policy. The daemon's
separate private configuration defines named store adapters, resource profiles,
global policy, listeners, and limits. Session grants are established by the
trusted control plane, not by entries supplied by an agent.

Both configuration files carry the same positive integer
`configuration_revision`. They form one configuration snapshot. A loader MUST
reject a mismatched pair rather than combining revisions. `schema_version`
describes the format; `configuration_revision` identifies an operator update;
neither is an item credential version or evidence of authority by itself.

## Version-1 example

All labels and references below are synthetic. Store keys are deliberately
opaque; the example does not identify a real SQLite or Keychain record.

```json
{
  "schema_version": 1,
  "configuration_revision": 1,
  "items": [
    {
      "item_id": "item-work",
      "label": "Work account",
      "account_alias": "work",
      "profile": "work-site",
      "credential": {
        "store": "default",
        "key": "opaque-backend-reference"
      },
      "approval": "authenticate"
    }
  ]
}
```

| Field | Contract |
| --- | --- |
| `schema_version` | Required integer, exactly `1` |
| `configuration_revision` | Required positive integer; matches the daemon configuration snapshot |
| `items` | Required bounded array; empty is permitted and grants no access |
| `item_id` | Unique stable alias; never the native store key |
| `label` | Explicitly approved display label; not copied automatically from private store metadata |
| `account_alias` | Safe account selector; not implicitly the real username |
| `profile` | Existing reviewed resource profile; not an agent-selected origin |
| `credential.store` | Existing adapter alias supplied by trusted composition; not a library, executable, or remote URL to load |
| `credential.key` | Nonempty, bounded, backend-private reference to one coherent credential item |
| `approval` | `inherit`, `authenticate`, or `always`; omitted means `inherit` |

Item, account, profile, and adapter aliases use 1–64 ASCII characters matching
`[A-Za-z0-9][A-Za-z0-9._-]*`. Labels are bounded UTF-8 display text without control
characters. Backend keys are opaque bounded strings interpreted only by the
selected adapter; never derive an origin, username, or authorization from them.
For binary native references the adapter specifies an encoding and validates it.
The file does not contain passwords, credential fingerprints, store unlock keys,
cookies, placeholders, or live authentication contexts.

One catalog entry binds one item/account to one profile. Reusing the same native
credential for another profile requires another explicit enrollment and grant;
it does not broaden an existing binding. Native reference resolution must not
silently select a same-named replacement when the enrolled item disappears.
The initial catalog confers read/use authority only, never permission to update
or delete a native item.

The store supplies field kinds and a coherent current credential version.
The profile supplies selectors, username visibility, destinations, and response
handling. These values are not duplicated into the catalog, and live versions
are not persisted here. API-key profiles must refer back to an item enrolled
for that profile; login profiles must be compatible with the item's available
field kinds before issuance or use.

## Policy composition

`inherit` adds no item-specific approval requirement. It does not mean "allow"
and cannot cancel global, session, or action-level requirements. `authenticate`
requires approval for a credential-bearing authentication operation. `always`
also requires approval for each protected operation using a private cookie or
token context. API-key injection is authentication on every request, so both
modes require approval on those requests. See [approval semantics](approval.md).

Global and session policies establish the minimum requirements. A route or
item can add requirements but cannot relax them. Independent deny decisions
win; a human confirmation never grants a missing destination/account/action.
Policy applies to the selected catalog binding even when multiple entries
refer to one native credential.

## Privacy and safe opening

Locations and filesystem requirements are defined in
[secret stores](secret-stores.md#private-catalog-and-policy-metadata):
owner-only `0700` directories and `0600` regular files, including temporary
files and backups. Apply descriptor-based ownership, mode, file-type, link,
ACL, and safe-path checks before reading or replacing anything. Do not print
the catalog or native references in validation errors or ordinary logs.

Keep the catalog, configuration, and backing store outside sandbox mounts.
Permissions alone do not isolate another process with the daemon's UID.
An encrypted secret store does not encrypt this metadata; disk encryption or
an explicitly designed encrypted catalog would be additional protections.

## Enrollment, updates, and reload

Trusted enrollment proceeds as follows:

1. Select an accessible native item or create an explicitly managed item
   through the store's administrative interface. Never enumerate the full
   native store through agent tools.
2. Review the resource profile and choose safe aliases, label, and item policy.
3. Validate the complete candidate configuration and catalog, including their
   shared revision and all cross-references, before publication.
4. Write private temporary files, synchronize them, and atomically replace each
   file through the validated parent directory. Retain only private backups.
5. Request an explicit reload. Install one immutable in-memory configuration
   generation only after the complete pair has passed validation.

Two file replacements are not one filesystem transaction. A crash or reader
between replacements can see a revision mismatch: startup then fails closed,
and a running daemon retains its last valid generation. Do not automatically
fall back to an older configuration, which could restore revoked access.
Recovery is an explicit operator action using a validated matching pair.
Matching revisions detect mixed updates, not restoration of an entire older
pair. They are not cryptographic integrity or rollback protection against an
operator/host that can replace both files.

A failed reload leaves the previous generation active and reports a safe
failure; it is not evidence that a requested revocation took effect. The
operator must verify successful reload or explicitly revoke/stop affected
sessions through the independent control plane.

On successful reload, invalidate contexts and pending work for removed or
changed item/profile bindings. Changes to store references, credential field
policy, destinations, or approval requirements require fresh authentication
preparation. Recheck remaining operations against current grants before
dispatch. Do not mutate a queued operation into different work. Native item
rotation is detected through the store contract, independently of catalog
reload. Unenrollment removes the binding, never the existing Keychain item.

The [operator lifecycle](operations.md) defines partial enrollment failures,
the distinction between unenrollment and native deletion, and recovery without
silently restoring old grants. Catalog publication and native item mutations
are separate transactions; neither may imply success of the other.

## Acceptance checks

- Parse the example, reject unknown versions/members and duplicate JSON keys,
  and reject duplicate aliases and missing store/profile references.
- Reject mixed configuration revisions, malformed native references, excessive
  input, and profiles incompatible with the selected credential fields.
- Reject unsafe owner/mode/ACL, symlink/hard-link, and parent-path cases on
  initial load, update, and reload; leave the old file intact on failed writes.
- Exercise interruption between file replacements: no mixed generation is
  installed, and recovery never silently restores older authority.
- Tightening policy or removing an item blocks new dispatch and prevents late
  responses from reviving its private cookie context.
- Agent discovery exposes only authorized projections, never this document's
  full item representation or native store references.
