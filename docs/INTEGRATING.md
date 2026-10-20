# Integrating a real application

Start with a non-production resource and two synthetic identities. The free
edition requires a cooperating probe endpoint. It does not infer authorization
from a generic web page or treat a status code as proof of revocation.

1. Select one operation whose authorization matters, such as reading a particular
   non-sensitive test document. Specify the stable resource identifier.
2. Add a GET probe that uses the application's actual credential validator and
   policy evaluator for that operation. It should report the decision without
   performing a write. Follow [the response protocol](PROTOCOL.md).
3. Preserve the subject's existing credential. Give the control identity a separate
   credential that remains authorized for the exact same configured resource.
4. Establish a baseline. Every subject and control request must succeed. An invalid
   credential or missing control prevents a useful before/after comparison.
5. Perform your usual administrative intervention separately. Lite makes no
   identity-provider or resource-policy changes.
6. Run check or watch with the original baseline and credentials. Inspect explicit
   residual access and uncertain results before drawing conclusions.

The endpoint must return the actual authenticated identity and real credential
expiry. Fabricated identities or arbitrary future expiry destroy the observation's
meaning. For an opaque credential, the application must obtain validity and expiry
from its trusted validator; this protocol does not guess them.

The current Lite release supports Bearer credentials only. It has no browser-cookie
extraction, refresh-token automation, SAML client, Kerberos integration, generic
identity-provider administration, Nmap integration or packet decoder. Those are
not silently included by calling the protocol provider-neutral.

A policy-denied but still-authenticated credential supports a bounded denial
result. An authentication-invalid credential currently yields UNKNOWN. This
conservative first protocol cannot establish which administrative action caused
authentication invalidity. An application may be protected while the tool still
reports UNKNOWN; that is a known interpretation boundary.
