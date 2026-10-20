# Validation and benchmark interpretation

The test suite targets input validation, credential handling, HTTP refusal cases,
baseline binding, temporal interpretation, state aggregation, evidence validation,
CLI behavior and local laboratory lifecycle.

The `benchmark` command evaluates the decision classifier against separately
expressed expected outcomes for a bounded synthetic matrix. It reports exact
case and mismatch counts. This measures classifier correctness
for that matrix; it is not network throughput, provider compatibility, a customer
pilot or a comparison against other security products.

The `demo` command uses actual loopback HTTP with fresh synthetic credentials and
an ephemeral owned server. It exercises actual client, protocol, engine and evidence
code. All resources and decisions remain controlled fixtures. A passing demo does
not establish identity-provider support or production fitness.

Record the exact archive hash, interpreter version and test results for each
candidate. External reproduction and independent engineering review are separate
from tests run by the implementation team. Zero observed false success in a finite
suite is not a mathematical guarantee about future environments.
