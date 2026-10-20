# Lite 0.1 implementation contract

This is a separate implementation, not an extraction of the private service.
Python 3.11+, standard library runtime, Linux first, entirely terminal operated.
No administrative mutations, telemetry, cloud account or production claim.

## Shared interfaces

`common.py` owns frozen `Resource(id, url)` and `RuntimeConfig(subject_id,
control_id, subject_token, control_token, resources, timeout_seconds=3,
max_response_bytes=16384, freshness_seconds=30, allow_http_loopback=False)`.
It supplies safe `AssuranceError(code)`, canonical JSON, timestamps, bounded
JSON reads, private exclusive writes and private credential-file reads.

`config.load_config(path, *, allow_http_loopback=False) -> RuntimeConfig`.
Config schema `access-assurance-lite/config-v1`, subject/control objects with
`id` and `token_file`, resource array with `id` and `url`, optional
`timeout_seconds`, `max_response_bytes`, `freshness_seconds`.
Paths resolve relative to config. Unknown keys and malformed data rejected.
Up to 16 resources; distinct identities and distinct credentials.

`transport.probe(config, resource, role) -> dict` where role is subject/control.
Returns bounded, secret-free observation with `decision` ALLOW/DENY/UNKNOWN,
`reason`, `credential_valid`, `observed_at`, `duration_ms`, `subject_id`,
`resource_id`. Failures return UNKNOWN. No response body/header/token output.

Probe protocol: GET exact configured URL, Bearer authorization,
`X-Assurance-Challenge` random per request, `Cache-Control: no-store`.
Response JSON schema `access-assurance-probe/v1`, exact matching `challenge`,
`subject_id`, `resource_id`, `decision` ALLOW/DENY, boolean `credential_valid`,
`reason` ACCESS_ALLOWED/POLICY_DENIED/CREDENTIAL_INVALID, `credential_expires_at`
UTC timestamp. ALLOW must be HTTP 200; valid POLICY_DENIED must be HTTP 403.
Only explicit valid-credential policy denial can establish bounded verification.
No redirects, proxies, insecure TLS, compressed or oversized responses.
HTTP only with CLI opt-in and literal loopback IP. Timeout and response limits.
The cooperating resource is a declared trusted observation source.

`engine.baseline(config) -> dict` and `engine.check(config, baseline_doc) -> dict`.
Baseline requires observed subject and control ALLOW for every configured resource.
Bind config scope and original credentials without storing secrets; hard maximum
baseline lifetime 24h. Three observations per check: control, subject, control.
RESIDUAL when valid subject ALLOW is observed; VERIFIED only when subject DENY
with valid credential and both controls ALLOW; otherwise UNKNOWN. Aggregate
RESIDUAL wins, then UNKNOWN, then VERIFIED. Freshness bounded by credential expiry
and observations. Baseline failure is an operator-safe error. Evidence is hashed,
not signed; hash alone is not source authenticity. Recheck original credentials.

`evidence.seal(payload) -> envelope` / `evidence.verify(envelope) -> dict`;
strict bounded structural/semantic validation and integrity, always historical.
Never claim current state from a saved document. `engine` returns sealed envelopes.

`lab.run_demo(output_directory) -> dict`: ephemeral loopback HTTP server with
generated secrets and real HTTP probes; baseline, denied subject, restored access,
outage/failed control. Always stop owned server. Write exclusive private artifacts.
`benchmark.run_benchmark() -> dict`: reproducible truth-table/negative scenario
evaluation, expressly synthetic, no external user/provider performance claims.

CLI: doctor, init, baseline, check, watch, inspect, compare, demo, benchmark.
Bounded watch, machine JSON, readable monochrome output, deterministic exit codes,
no secrets on command line and no raw exceptions.
