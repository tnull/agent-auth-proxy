# aap-client

Credential-free `AgentService` client for one host-provided Unix session socket.
It has no engine, credential store, private cookie, CA, or upstream TLS
dependency. Identity comes from the attachment, never a caller-supplied session
ID. The sandbox must expose only its own socket; peer UID alone is insufficient
to isolate same-user agents.

Calls use one bounded HTTP/1.1 connection, with no redirect or retry. Errors
after sending begins may be uncertain; use the same request ID for status or
duplicate submission, or call cancel explicitly. Dropping a response closes
the local connection but is not proof that upstream work was undone.
