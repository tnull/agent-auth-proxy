# First hands-on demo (Linux)

This is a runnable synthetic experiment, not a production deployment. It starts
the **actual standalone daemon**, a small loopback HTTPS fixture, an encrypted
SQLCipher vault, and a session you can access through the real stdio MCP bridge.
It does not call paid providers, enroll personal credentials, modify Goose, or
install a system CA. macOS/Keychain work is deferred.

## Start

Prerequisites: Linux, Bash, the repository's Rust toolchain (1.95.0), a C compiler,
`pkg-config`, and OpenSSL development headers/libraries. No Python, Docker,
Node, API key, or model subscription is needed for the walkthrough.

From the checkout:

```sh
./scripts/demo.sh
```

If this host supplies Rust 1.95.0 under `stable` instead of the pinned toolchain
name, use `RUSTUP_TOOLCHAIN=stable ./scripts/demo.sh`.

The launcher builds only the daemon and demo executable. Unless you set
`CARGO_TARGET_DIR` to an existing task-specific build directory under `/tmp`,
it allocates a fresh one there and prints its location. Reuse that printed
directory for subsequent builds to avoid recompiling dependencies.

It then:

1. Creates `$HOME/.aap-demo/` with owner-only permissions, synthetic credentials, and a
   random SQLCipher key. Later starts reopen the same vault without replacing
   its credentials.
2. Starts a loopback-only HTTPS fixture and the real daemon with an exact
   hostname/IP/route allowlist and explicit ephemeral TLS trust.
3. Runs an MCP walkthrough: provider-key injection, item lookup, fake
   credentials, CSRF, form login, protected-resource access, and logout.
   The fixture deliberately echoes credentials; the walkthrough requires
   those echoes to be redacted. A post-logout request must be denied.
4. Prints the connection details and keeps serving for up to one hour.
   Sanitized observation records stream as JSON lines on stdout. Human
   startup/status messages go to stderr. Stop with Ctrl-C.

For a self-contained pass/fail demonstration that exits:

```sh
./scripts/demo.sh smoke
```

Success prints a JSON report with `"demo": "passed"`, the fake password,
protected data, and the number of inspected observation records. Failure exits
nonzero. The state remains available for a later interactive `serve` run.

## Connect an MCP client or agent

While `serve` is running, `$HOME/.aap-demo/mcp.json` contains a common MCP configuration
fragment with an absolute executable path and arguments:

```json
{
  "mcpServers": {
    "aap-demo": {
      "command": "<build-directory>/debug/agent-auth-proxy",
      "args": ["mcp-bridge", "<state-directory>/r/<session>.sock"]
    }
  }
}
```

Use the **generated values**, not these placeholders. Clients with a different
configuration format need the same command and argument list entered in their
MCP server settings. No client-specific integration has been installed or
verified. Restart/reconnect the MCP client after restarting the demo: session
attachments and the fixture's port change each time.

`$HOME/.aap-demo/agent-prompt.txt` supplies the exact resource names, current URLs, and
login sequence for an agent. Tools advertise their input schemas. The seven
tools include `vault.search_items`, `vault.get_login`, `request.execute`,
`vault.auth_status`, and `vault.logout`; see [MCP details](mcp.md).
The provider fixture returns fixed synthetic text, **not a real LLM**. An agent
you attach still needs its own model setup; this demo does not configure that.

To repeat the complete MCP walkthrough from another terminal, without an LLM:

```sh
./scripts/demo.sh check
```

This connects to the currently running session and uses only its agent-facing
socket. Its traffic appears in the serving terminal's observation stream.
The successful startup walkthrough's observation records have already been
checked and acknowledged; `check` generates fresh traffic to watch. Repeated
checks consume the ordinary context/login-attempt limits; restart after the
demo reaches a limit, rather than expecting unlimited synthetic logins.

## State and boundaries

- `$HOME/.aap-demo/c/`: generated private catalog/configuration; `s/`: SQLCipher
  vault; `r/`: operator, observation, and session sockets. Configuration
  is regenerated on startup for the new fixture certificate/port, not a place
  to enroll real sites. All files are `0600`; directories are `0700`.
- `$HOME/.aap-demo/demo-unlock.key` is a **demo-only convenience**: the random unlock key
  is stored beside the encrypted vault and passed to the daemon on private
  stdin, never as an argument/environment variable. This is not protection
  against someone who can read the entire state directory. Use synthetic data
  only. No general-purpose production provisioning workflow is implied.
- This launcher **does not sandbox the agent**. A same-user unsandboxed agent
  may read the state directory or bypass the proxy. Demonstrating custody on
  the mediated path is not proving mandatory interception. Use the separate
  [confinement tests](confinement.md) for existing sandbox evidence. Do not
  expose this state directory or operator sockets to an untrusted agent.
- Give an MCP client only the bridge command/session attachment. Observation
  is redacted but may still contain prompts and ordinary private content.
  Required recording is bounded local memory, not durable capture; a stalled
  consumer can cause requests to fail closed.
- The small demo covers one provider-style JSON response and one form login.
  It does not enable CONNECT, remote MCP, TCP, signed human approval, or arbitrary
  browser compatibility; those components have separate fixture suites.
- Stopping retains the vault/key/configuration. Restart creates new sessions;
  old attachments are invalid. A second launcher on the same directory is
  refused. Shutdown/recovery is not a complete production lifecycle guarantee.

An optional second argument selects another **dedicated**, short state path:
`./scripts/demo.sh serve /absolute/private/demo-state`. The parent must already
exist and pass the repository's safe-ancestor checks; the final path must be at
most 70 bytes to accommodate Unix sockets. Existing unknown, incomplete, or
unsafe directories are refused, never repaired or silently replaced. If an
initialization was interrupted, choose a fresh directory and inspect the old
one separately. To reset, stop the demo and choose a new dedicated directory;
there is no automatic recursive deletion command.

## Verification

`cargo test --locked -p aap-daemon --test demo` runs the same bootstrap and real
stdio MCP walkthrough twice against one persisted encrypted vault. It verifies
file permissions, refusal of concurrent/unknown state, unchanged vault/key on
restart, fresh session/daemon identity, and normal socket cleanup. Set
`AAP_TEST_ROOT` to a trusted existing parent if the host's `/tmp` ancestry is
unsafe; build artifacts still belong under `/tmp`.
