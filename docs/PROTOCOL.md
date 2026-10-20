# Cooperating-resource protocol v1

The operator chooses an exact endpoint that authenticates the supplied existing
Bearer credential and evaluates access to the named resource without mutating it.
It must exercise the same relevant authorization path as the application action
being assessed. An unrelated health endpoint is not a substitute.

Request: GET the configured HTTPS URL, `Authorization: Bearer <credential>`,
`X-Assurance-Challenge: <fresh challenge>`, `Cache-Control: no-store`.
No redirect following or automatic token refresh is permitted.

A successful response is HTTP 200 with this JSON structure:

```json
{
  "schema": "access-assurance-probe/v1",
  "challenge": "echo-the-request-challenge",
  "subject_id": "subject-example",
  "resource_id": "resource-example",
  "decision": "ALLOW",
  "credential_valid": true,
  "credential_expires_at": "2030-01-01T00:00:00Z",
  "reason": "ACCESS_ALLOWED"
}
```

The timestamp above only illustrates syntax. Respond with the actual verified
credential expiry. The resource must verify issuer, audience, signature and expiry
according to its own authentication mechanism before asserting credential validity.
Lite does not decode a token and pretend that parsing verifies its signature.

Explicit policy denial is HTTP 403, decision `DENY`, reason `POLICY_DENIED`,
`credential_valid: true`, with the same scope and challenge fields. A rejection
because a credential is expired, invalid or no longer authenticated cannot establish
bounded policy denial in this initial protocol. Return `CREDENTIAL_INVALID` and
false validity; Lite treats it as unknown. This deliberately narrow distinction is
documented and does not claim to characterize every valid revocation mechanism.

The body is UTF-8 JSON with Content-Type `application/json`, without content
encoding. Unknown fields, duplicate keys, mismatched challenge/identity/resource,
unexpected HTTP status and inconsistent decision/reason are rejected. Subject
and control requests use different credentials and identities. A valid fresh
control ALLOW must occur before and after a subject DENY to support `VERIFIED`.

The server in `src/assurance_lite/lab.py` is a reference for the wire format, with
synthetic in-memory authentication. It is not production authentication code and
is never an identity-provider integration claim.
