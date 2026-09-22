# aap-config

Private configuration-file access for trusted hosts and store adapters. This
crate keeps filesystem policy separate from pure authorization and the portable
secret-store interface. It is not an agent API or a configuration framework.

The Linux implementation uses descriptor-relative operations, no-follow opens,
owner/mode/type/link checks, and conservative POSIX ACL rejection. Reads are
bounded; replacement files are private from creation and synchronized before
rename. It never fixes unsafe permissions silently or discovers environment
paths inside a reusable library. The caller validates configuration semantics
before writing and installs complete configuration generations atomically.

Other platforms require their actual ACL semantics to be implemented and tested
before they are supported. Owner-only access does not isolate another process
with the same UID; sandbox filesystem confinement remains necessary.

The only added OS dependency is the safe
[rustix descriptor API](https://docs.rs/rustix/latest/rustix/fs/fn.openat.html),
including [descriptor-based attributes](https://docs.rs/rustix/latest/rustix/fs/fn.fgetxattr.html).

Tests create fresh private fixture directories under `/tmp` by default. That
parent must have safe ancestor permissions (normally root-owned sticky `/tmp`).
On an unusual host with an unsafe temporary parent, set `AAP_TEST_ROOT` to a
trusted existing parent for filesystem fixtures. This does not weaken checks,
change process permissions, or move Cargo build artifacts out of `/tmp`.
