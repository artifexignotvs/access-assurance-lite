# 0.1.0a1 public alpha

Access Assurance Lite makes the access-verification workflow independently usable
from a terminal. The free edition's source is MIT-licensed; the commercial
application remains private.

Download `access-assurance-lite.pyz`, verify its digest against `SHA256SUMS`, and
run it with Python 3.11 or newer on Linux:

```sh
python access-assurance-lite.pyz doctor
python access-assurance-lite.pyz demo --directory first-demo
python access-assurance-lite.pyz benchmark --json
```

The demo makes actual HTTP requests to two synthetic loopback resources. It
demonstrates a working baseline, explicit policy denial, returned access, outage,
failed controls and recovery. It creates private evidence files and shuts down
its owned server. No existing accounts or services are modified.

For real application use, implement the cooperating-resource protocol, configure
the exact endpoints, and supply two private existing Bearer credentials. See
the README and integration guide. Generic HTTP status codes do not establish
revocation. Hash evidence establishes consistency, not source authenticity.

The local validation suite contains 97 tests. The separately labeled synthetic
classifier corpus contains 118 scenarios. Reported counts describe these bounded
inputs and do not establish production fitness, external audits or universal
compatibility. The hosted workflow evaluates supported Python versions.

## Edition boundary

Lite includes local checking, watch, comparison, evidence and export. The private
commercial candidate retains approval roles, tenant/site controls, execution
workflows, bounded planning, signed history and controlled recovery. Broader
commercial operation still needs independent pilots and productization.
