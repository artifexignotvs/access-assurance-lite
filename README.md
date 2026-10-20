# Access Assurance Lite

**An account was disabled. Can its existing credential still reach the application?**

Lite is a local command-line checker for a bounded answer. It records a working
baseline, checks the same credentials after an operator's intervention, and
distinguishes observed residual access, explicit policy denial and uncertainty.

Public alpha **0.1.0a1**. Runtime: Python 3.11 or newer on Linux.
No runtime package dependencies, account registration, telemetry or hosted service.
MIT-licensed Lite source. The separately maintained commercial core remains private.

## Try the complete local demonstration

Download the executable archive from [Releases](https://github.com/artifexignotvs/access-assurance-lite/releases)
and run `python access-assurance-lite.pyz --help`. Or use this source checkout:

```sh
PYTHONPATH=src python -m assurance_lite doctor
PYTHONPATH=src python -m assurance_lite demo --directory ./first-demo
PYTHONPATH=src python -m assurance_lite benchmark --json
```

The demo creates its own loopback server and fresh synthetic credentials, makes
real HTTP requests, exercises changing access decisions, writes private evidence
files and stops its server. It does not connect to an identity provider or modify
your accounts. The destination must not already exist.

Build a portable executable archive with the standard library:

```sh
python scripts/build.py dist/access-assurance-lite.pyz
python dist/access-assurance-lite.pyz doctor
python dist/access-assurance-lite.pyz demo --directory ./archive-demo
```

The archive requires Python; it is not an opaque native binary or source protection.
Repeated builds from identical source produce identical archive bytes.

## What is included

* Up to 16 explicitly configured application resources per assessment.
* Original subject credential and a distinct positive-control credential.
* Working baseline with scope and credential binding.
* Three observations per resource: control, subject, control again.
* `VERIFIED`, `RESIDUAL` and `UNKNOWN` outcomes with bounded freshness.
* Repeated checks, non-overwriting numbered local outputs and state comparison.
* Transition timeline and time to first observed denial, measured from watch start.
* JSON evidence, historical inspection and CSV export.
* Stable exit codes for scripts and CI.
* A cooperating-resource protocol, runnable local demonstration and synthetic
  correctness benchmark with an independently expressed expected outcome.

## Check your application

Your application must implement the small [probe protocol](docs/PROTOCOL.md).
An arbitrary HTTP 403 is insufficient: it might be an expired credential,
rate limit, WAF response or unrelated error. The protocol explicitly reports
the authenticated identity, valid credential and policy decision.

```sh
PYTHONPATH=src python -m assurance_lite init --directory ./assessment
```

Edit `assessment/config.json` with your resource URLs and identities. Place the
two existing test credentials in distinct files named by the configuration;
the files must belong to your user and have mode `0600`. The initializer does
not create credentials. Credential values never belong in command arguments.

```sh
PYTHONPATH=src python -m assurance_lite baseline \
  --config assessment/config.json --out assessment/baseline.json

# Mutatio extra instrumentum: use your normal access administration process.

PYTHONPATH=src python -m assurance_lite check \
  --config assessment/config.json --baseline assessment/baseline.json \
  --out assessment/after.json --json

PYTHONPATH=src python -m assurance_lite watch \
  --config assessment/config.json --baseline assessment/baseline.json \
  --directory assessment/watch --count 10 --interval 2 --json

PYTHONPATH=src python -m assurance_lite inspect assessment/after.json \
  --csv assessment/after.csv

PYTHONPATH=src python -m assurance_lite compare \
  assessment/watch/check-0001.json assessment/watch/check-0010.json
```

HTTPS uses normal certificate validation. Explicit `--allow-http-loopback`
permits plain HTTP only for literal loopback addresses for your local lab.
Environment proxies and redirects are disabled. The probe is a GET request to
the exact configured endpoint; Lite does not scan networks or execute commands.

| Exit | Meaning |
| --- | --- |
| 0 | Baseline ready, bounded check verified, or successful utility command |
| 2 | Valid subject access remains in at least one observed resource |
| 3 | Check cannot establish bounded denial |
| 4 | Invalid input, invalid evidence or operation failed |
| 130 | Interrupted by operator |

`inspect` returning 0 means that a historical document passed validation. It does
not mean access is currently absent. A watch exit code describes its final sample;
earlier transitions remain in its numbered evidence files.
The watch summary also records transitions, residual/unknown sample counts and
time to first observed `VERIFIED`. Its clock starts when watch starts, not when an
administrative operation occurs; this is not a causal revocation-latency claim.
`summary.json` distinguishes a complete run, a reached scheduling limit, an error
and an operator interruption. On an error or interruption, completed evidence
files remain and Lite attempts to preserve a partial summary with a safe error
code. A previous `VERIFIED` sample does not make an incomplete run successful:
errors and scheduling cutoffs exit with 4; operator interruptions exit with 130. A process kill or an
unwritable destination may prevent the summary from being saved. Files are never
overwritten by Lite; this does not make them immutable to their owner.

## Interpret the boundary

`VERIFIED` means explicit denial of the original valid subject credential while
both positive-control probes succeeded for the configured resources in the
observation window. It does not establish revocation of every session, coverage
of hidden paths or future absence. Checks are sequential, not an atomic snapshot.
The resource is trusted to report its authentication and authorization honestly.

A fresh explicit subject ALLOW establishes `RESIDUAL` even when another resource
is unknown. Otherwise any failed, stale, unsupported or ambiguous observation
prevents `VERIFIED`. Credential expiry is not successful revocation.

Evidence contains hashes for accidental corruption detection and binding, **not
digital signatures or independent source authenticity**. Anyone able to rewrite
an artifact and its digest can construct a new document. Saved results are always
historical. Private output files can include your application URLs and identity
labels; review them before sharing.

See [edition boundaries](docs/EDITIONS.md), [security](SECURITY.md),
[benchmark interpretation](docs/VALIDATION.md), [application integration](docs/INTEGRATING.md)
and [distribution terms](DISTRIBUTION.md).

## Development checks

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The tests and demo are local evaluation. External reproduction, customer pilots,
production compatibility and a measured productivity advantage remain unproven.
