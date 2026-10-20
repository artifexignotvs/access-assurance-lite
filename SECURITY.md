# Security boundaries

Lite is an observation client. It performs GET requests against endpoints supplied
by its local operator. It cannot disable users, terminate sessions, rotate keys or
change policy. Configure endpoints where a GET has no administrative side effects.

The cooperating resource and local operator host are trusted. TLS checks the
configured server certificate; the local HTTP exception is deliberate and limited
to literal loopback addresses. Redirects, ambient proxies, compressed responses,
duplicate JSON keys and oversized protocol responses are refused. There is no
insecure TLS option. Request I/O is bounded; operating-system DNS resolution and
multi-address connection setup may exceed the configured timeout. Late responses
cannot establish success. No strict wall-clock SLA is asserted. Watch bounds
the cycle count and stops scheduling new cycles after one hour; a cycle already
running may finish later. The configured interval is a pause between completed
checks, not a guaranteed sampling period.

Credential files must be private regular files, owned by the invoking user.
Symlinks, group/world-readable files, duplicate tokens and control characters are
rejected. Output artifacts are created exclusively with mode 0600. Demo and watch
directories are newly created with mode 0700. Existing files are not overwritten.
Keep these directories inside a location you control.

Responses, headers and exception bodies are not copied into reports. Token
material stays out of recorded observations. Scope documents include explicitly
configured URLs and subject/control labels and therefore still need review before
sharing. No general-purpose personal-data redaction is claimed.

The protocol binds a fresh request challenge, identity and resource to a decision.
This prevents accepting ordinary cached protocol responses; it cannot make a
compromised or dishonest resource report truthfully. Positive controls improve
interpretation but cannot prove universal absence or causal attribution of a
particular administrative operation. Baseline binding prevents accidental use of
different credentials; it is not a signature or external trust anchor.

Saved evidence verification is structural, semantic and hash based. It is never
a currentness check against the resource. A new observation is necessary for a
new access decision. Measurements from multiple resources occur at different times.

Use synthetic identities when reporting defects. Never include credentials,
private tokens, live internal URLs or raw confidential artifacts in public issues.
