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
not exposed by this initial API-key path. Website-specific capture, placeholders,
cookie sessions, and CSRF support are separate pending work. New Set-Cookie
values are captured for echo suppression, but this API-key path does not retain
or send them on subsequent requests.
