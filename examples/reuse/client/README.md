# Credential-free client consumer

Build this manifest independently from the root workspace. The binary accepts
one bounded JSON job on stdin containing two already-admitted session socket
paths and a synthetic origin, then returns a bounded report of public responses,
metadata, errors, and operation outcomes. It is given no operator attachment,
store, catalog, CA-key, or upstream credential. The trusted harness checks this
report for managed-secret exposure. Never use this acceptance program against
real accounts; its report contains live fake credentials and is not ordinary
production telemetry.

Its integration test is a separate trusted harness which provisions SQLCipher,
starts the real daemon, creates attachments, launches the binary with a cleared
environment, and checks upstream receipts and private observation. Build the
root daemon and set `AAP_DAEMON` to its absolute executable path before running
this manifest's tests. Use `AAP_TEST_ROOT` for safe temporary private fixtures
when required by the host; all build output belongs under a fresh `/tmp` target.

The normal/build dependency closure must remain credential-free even though
the trusted integration test needs store and policy development dependencies.
Both login encodings are exercised through the shared scenario source.
See [the common commands](../README.md#run-both-consumers). This test clears the
client environment but does not place the client in an OS sandbox; it proves
the program/API boundary, not filesystem or network confinement.
