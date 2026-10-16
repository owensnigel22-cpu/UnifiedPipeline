# Keylab Cryptographic Analysis Notes

Keylab contains educational reference implementations and bounded SAT/CNF
experiments. They are not production cryptographic implementations, and
reduced-round experiments are not evidence of a break in full SHA-256.

This note covers quantum threat models, the separation between RIPEMD-160 and
secp256k1 signing nonces, and the optional Boolean equation DAG used to inspect
tracked SHA-256 CNF circuits. See the
[ECDLP feasibility note](./docs/ecdlp-feasibility.md) for summation-polynomial
context and bounded toy-experiment recommendations. The
[evidence-grounded agent workflow](./docs/evidence-grounded-agent-workflow.md)
is a reusable prompt template; it does not install or activate agents.

## 1. Quantum threats to cryptography

| Algorithm | Primary target | High-level impact |
| --- | --- | --- |
| Shor's algorithm | Integer factorization and discrete logarithms | Threatens RSA, finite-field Diffie-Hellman, and elliptic-curve systems on a sufficiently capable fault-tolerant quantum computer. |
| Grover's algorithm | Unstructured search | Gives a quadratic query-complexity improvement in idealized search models; it does not make symmetric cryptography trivially breakable. |

### Shor's algorithm

RSA relies on the difficulty of factoring its modulus. Diffie-Hellman and
elliptic-curve systems rely on discrete-logarithm problems. Shor's algorithm
would solve these problems efficiently on a sufficiently capable,
fault-tolerant quantum computer. Such a machine is not available today, and
the practical resource requirements matter.

The "harvest now, decrypt later" concern applies to information whose
confidentiality must persist: an adversary can record encrypted traffic now
and retain it for possible later decryption. It is a reason to plan migration
to standardized post-quantum key establishment, not evidence that current
traffic can already be decrypted this way.

### Grover's algorithm

Classical exhaustive search over `N` candidates takes `O(N)` queries in the
idealized model; Grover search takes `O(sqrt(N))` oracle queries. This motivates
larger symmetric keys and hash outputs where appropriate. The query bound does
not account for all circuit, error-correction, memory, or wall-clock costs.

| Primitive | Classical key/output size | Idealized Grover search scale |
| --- | --- | --- |
| AES-128 | 128-bit key | About `2^64` oracle queries |
| AES-256 | 256-bit key | About `2^128` oracle queries |

This table is a simplified search comparison, not a complete post-quantum
security estimate. Shor and Grover have different targets and implications:
Shor threatens public-key assumptions; Grover gives a quadratic search
speedup, rather than a general break of SHA-2 or AES.

## 2. RIPEMD-160, HASH160, and secp256k1 nonces

RIPEMD-160 and secp256k1 ECDSA are different primitives. Bitcoin HASH160 is
computed as:

```text
public key -> SHA-256 -> RIPEMD-160 -> HASH160
```

ECDSA signing separately uses a message hash `z`, private key `d`, and signing
nonce `k`:

```text
r = (k * G).x mod n
s = k^-1 * (z + d*r) mod n
```

The ECDSA nonce does not occur in public-key address derivation. Recovering a
preimage of RIPEMD-160 alone therefore does not reveal an ECDSA nonce or private
key. Even a candidate public key matching an address hash would not itself
reveal its private key; that would require solving the elliptic-curve
discrete-logarithm problem.

Known classes of nonce failures include nonce reuse, exploitable nonce bias
or leakage, predictable randomness, and certain fault attacks. Their success
depends on specific signing data and leakage assumptions. There is no valid
general mathematical bridge from a partial RIPEMD-160 state to a secp256k1
nonce.

The reference `scalar_mult` uses a lazily cached four-bit table when
multiplying the fixed generator, reducing repeated point additions for
public-key derivation. Arbitrary-point multiplication keeps the double-and-add
path. This Python implementation is variable-time and is not suitable for
production ECDSA signing or secret-key operations.

## 3. Partial assignments and undetermined circuit state

A SAT solver's complete model assigns values to every variable in that model.
During propagation, however, only a subset may be implied by a partial input
assignment. A three-valued circuit evaluation labels each node `true`,
`false`, or `unknown`; it is useful for:

- finding missing or incorrect gate wiring;
- distinguishing determined subgraphs from unconstrained portions;
- inspecting candidate cut points for cube-and-conquer experiments.

An `unknown` result is a statement about the current partial assignment and
the tracked Boolean DAG. It is not a proof that a node is globally free or
that a cryptographic equation is underdetermined.

## 4. Optional Boolean equation DAG

`EquationDAG` validates that each gate refers only to earlier nodes, rejects
duplicate variable definitions, supports signed CNF literals, and evaluates
Boolean gates using three-valued propagation. `CNF(track_dag=True)` records
inputs and Boolean gate outputs while retaining the regular DIMACS clauses.
Tracking is opt-in so existing models do not pay the memory cost.

The current SHA-256 encoder represents arithmetic as its underlying XOR and
majority gates; it does not collapse a word adder into an opaque `ADD` node.
The exported DAG describes circuit dependencies and gate semantics. CNF
constraints such as the requested target digest and fixed input bits remain
in the DIMACS formula rather than being represented as circuit nodes.

Example:

```python
from keylab.hashes.sha256_cnf import sha256_hash_preimage_cnf
from keylab.sat.dag import Tri

model = sha256_hash_preimage_cnf(
    bytes(32),
    message_length=1,
    rounds=1,
    track_dag=True,
)
assert model.formula.dag is not None
partial_values = model.formula.dag.evaluate({model.input_bits[0]: True})
variable_values = model.formula.dag.variable_values(partial_values)
```

Generate a bounded formula and export its tracked circuit:

```powershell
keylab sha256-cnf --mode hash --target <64-hex-digest> `
  --rounds 14 --message-length 3 --output model.cnf `
  --track-dag --dag-output model.dag.json
```

The export can be loaded in a debugger or processed as JSON. `Tri.UNKNOWN` is
reported for a node only when its value can vary over the completions of the
current partial assignment.

## 5. Local Markdown preview style

The VS Code Markdown preview uses [the workspace stylesheet](.vscode/markdown.css).
It removes link underlines, applies the selected link color, and adds borders
and a light header background to tables. It changes preview presentation only;
it does not alter the underlying Markdown or HTML output.

## SHA-256 backward boundary and solver benchmark

For the standard 64-round, one-block backward trace, the output feed-forward
allows the working state at round 64 to be calculated numerically. Reversing
the `a` recurrence reaches the boundary at round 59, where
`a56 = e60 - T1_59 (mod 2^32)`. The existing ledger regression vector records
`T1_59 = 0x4925e6bd` and a separate final-round equation
`h63 = 0x184a25d4 - W63 (mod 2^32)`. These are not evidence for
`e60 = 0x184a25d4 - W63`; the schedule dependency graph alone does not derive
that relation. See the `sha256-backward-ledger` command for the equations and
its stated assumptions. This is a numeric boundary analysis, not preimage
recovery.

Cube-and-conquer in the current SHA-256 CLI assigns selected free **input
bits**. The generated schedule words remain constrained by the CNF model;
the CLI does not directly assume bits of `W63`, `W62`, or `W61`. Those schedule
words are also absent from round-limited models that do not expand the
schedule through them. Thus a tri-variable schedule-word preset and its
reported timings are not included as verified workspace features.

The worker-scaling benchmark compares a known 16-byte reduced SHA-256 or
RIPEMD-160 preimage across worker-process counts. It reports wall time,
completed cubes per second, status, and speedup against one worker. Results
can be saved locally as CSV; values are measured when the command runs, not
pre-populated. A supported external SAT solver (`kissat`, `cadical`,
`cryptominisat5`, or `minisat`) must be available on `PATH`.

Run it from the project root in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m keylab.cli sat-throughput-benchmark --hash sha256 --rounds 15 `
  --cube-depth 4 --workers 1 2 4 8 --csv-output scaling_results.csv
```

Use the **Benchmark: Multi-Core Scaling (1 vs 2 vs 4 vs 8 Workers)** launch
configuration to run the benchmark from VS Code. It writes measured data to
`scaling_results.csv` in the workspace root and prints the summary to the
integrated terminal.

The command
`python -m keylab.cli hash-cnf-selftest --hash sha256 --rounds 16 18 20 22 24`
checks fixed-known-input CNF models at those round counts. It is a model
wiring self-test, not the worker-scaling benchmark or a W-word lookahead run.

## RIPEMD-160 verification scope

`tests/test_ripemd160_cnf.py` checks the implementation against five published
RIPEMD-160 reference vectors (empty input, `a`, `abc`, `message digest`, and
the lowercase alphabet). Its solver-backed known-input CNF test also covers
16, 32, 48, and 64 steps (as well as other step counts): it constrains the
known message bits, solves, then checks the recovered message and digest.
That confirms model consistency for those known inputs; it is not an
unconstrained preimage-recovery result or a separate proof of constant-folding
performance.

No `UnsupervisedAgentOptimizer`, `agent_learning_log.json` integration, or
W63/W62/W61 joint-cube bridge solver is present in this workspace. In
particular, no extended Pass A numerical state values or optimizer throughput
claims are treated as verified. The backward-ledger limitations are described
above.

### RIPEMD-160 CNF build measurements

The existing RIPEMD-160 CNF builder was measured locally at 16, 32, 48, 64,
and 80 steps, using the 13-byte message `b"keylab-stage3"` and its matching
reduced-step digest. Each build was timed five times; the table reports the
median formula-construction time. It does not include SAT solving or
serialization.

| Steps | Variables | Clauses | Median build time |
| ---: | ---: | ---: | ---: |
| 16 | 9,857 | 41,874 | 0.1432 s |
| 32 | 20,721 | 88,496 | 0.2285 s |
| 48 | 32,657 | 138,414 | 0.3146 s |
| 64 | 43,521 | 185,036 | 0.3910 s |
| 80 | 54,849 | 235,018 | 0.5325 s |

These are measurements from the configured workspace interpreter and will
vary by machine. They differ from other supplied figures and should not be
treated as universal performance numbers. The encoder does not count
constant-folded literals as a metric. Its internal constant map contained
161 unit-constrained variables in these models, but that count is not the
number of fold operations or folded literal occurrences. Constant folding is
performed during gate construction, alongside other simplifications; these
formula metrics alone do not separately benchmark propagation work.

### Bounded RIPEMD-160 input-cube smoke sweep

The available worker-scaling CLI was exercised with Kissat on its generated
16-byte target, at one reduced step and input-cube depths 1, 2, and 3. Each
run compared one and two worker processes. The benchmark now independently
recomputes every SAT candidate's digest; all six results were
`SATISFIABLE` with `candidate_validated=True`.

| Input-bit cube depth | Cubes in partition | 1 worker (s) | 2 workers (s) | Measured speedup |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2 | 0.5314 | 0.8472 | 0.63x |
| 2 | 4 | 0.4797 | 0.7571 | 0.63x |
| 3 | 8 | 0.4907 | 0.6408 | 0.77x |

These single-run timings include process-pool overhead and are only a smoke
measurement on a one-step reduced model. The solver stops after finding a
satisfying cube, so its reported cubes-per-second is completed cubes per
elapsed second, not a rate measured after processing every cube in the
partition. The test varies cube depth in the model's existing input-bit
order; it does not compare alternate message-bit selection orders or directly
assume RIPEMD message words. It is not a 16-, 32-, 48-, 64-, or 80-step
unconstrained preimage benchmark, and the solver status is `SATISFIABLE`, not
`OPTIMAL`.

The same free-input benchmark was also attempted at 16 steps, depth 1, one
worker, and a 5-second per-cube solver timeout. It returned `UNKNOWN` after
10.7002 seconds overall and produced no candidate to validate. This is a
bounded timeout result, not evidence of unsatisfiability.

## Local benchmark dashboard and development workflow

Install the optional developer and dashboard tools from the project root:

```powershell
python -m pip install -e ".[dev,dashboard]"
```

Run the worker-scaling benchmark with CSV output, then launch the local
dashboard:

```powershell
python -m keylab.cli sat-throughput-benchmark --hash sha256 --rounds 15 `
  --cube-depth 4 --workers 1 2 4 8 `
  --csv-output benchmark_reports\scaling_results.csv
python -m streamlit run dashboard\app.py
```

The dashboard accepts the benchmark CSV through upload or from the expected
local paths. Imported rows are deduplicated in
`benchmark_reports/benchmark_history.db`; reports can be downloaded as JSON.
CSV data and local databases are ignored by Git. Solver outcome summaries
distinguish `UNKNOWN` from timeouts: a timeout rate is not reported unless
explicit timeout data exists. CNF heatmaps and clause metrics are shown only
when the CSV carries the needed columns.

For formula structure metrics, `sha256-cnf` and `ripemd160-cnf` accept
`--diagnostics-output sat_report.json`. These record variable and clause
counts, average/maximum clause width, unit and empty clauses, and tracked
constant variables. Propagation strength is explicitly marked as unmeasured
because the current solver interface does not expose BCP statistics.

VS Code tasks provide focused SAT tests, the SHA-256 known-input check,
Ruff, scoped strict mypy for the dashboard/diagnostics additions, benchmark
execution, and dashboard launch. The Python editor is configured for strict
Pylance analysis, format-on-save, and Ruff fixes. Full-project typing issues
must be resolved before claiming every legacy module passes strict typing.
Property-based RIPEMD-160 comparisons use Hypothesis with bounded message
lengths.

The `.claude/agents/` files are role prompt profiles, and `.claude/config.yaml`
records the intended review order and quality gate. They are not a runnable
agent orchestrator in this workspace; triggering them requires a compatible
Claude host. The “Research Mode” remains a human-reviewed workflow: propose,
test, and benchmark changes before applying them; there is no autonomous
patch application.

## Scope and security notes

- Do not interpret reduced-round SHA experiments as attacks on standard
  full-round SHA-256.
- A timeout is `UNKNOWN`, not `UNSAT`, and does not establish a mathematical
  obstruction.
- Cryptographic code in this project is for education and research workflows;
  use well-reviewed libraries and standardized protocols for real security.

## Advanced demonstration suite

The modular `keylab` CLI and library remain the primary project interface. The
v17 trace and demonstration suite is also available as an installable command:

```powershell
keylab-advanced --help
```

Examples:

```powershell
keylab-advanced --pubkey-advance <PUBLIC_KEY_HEX> --steps 100
keylab-advanced --walkback-trace <ADDRESS_OR_PUBLIC_KEY>
keylab-advanced --sha256-backward-ledger <64_HEX_DIGEST>
keylab-advanced --sat-cnf <DIMACS_FILE>
keylab-advanced --rsa-demo
```

The advanced command retains the script's public-point walkback/tracing,
SHA-256 conditional backward ledger, SAT/CNF input, secp256k1 experiments,
and RSA demonstrations. Existing package functionality remains available
through `keylab` and its library modules.

## Optional accelerated backends

### Calling the RSA API from PowerShell

Run Python source through the virtual-environment interpreter. PowerShell itself
does not understand Python's `from` and `assert` statements:

```powershell
@'
from keylab.crypto import generate_rsa_keypair, rsa_oaep_encrypt, rsa_oaep_decrypt

keys = generate_rsa_keypair()
message = b"hello from Keylab"
ciphertext = rsa_oaep_encrypt(keys.public_key_pem, message)
assert rsa_oaep_decrypt(keys.private_key_pem, ciphertext) == message
print("RSA encryption round-trip passed")
'@ | .\.venv\Scripts\python.exe -
```

Install the RSA implementation first from the `UnifiedPipeline` directory with
`python -m pip install -e ".\keylab[crypto]"`.

Install the recommended native-backed set from the `keylab` project directory:

```powershell
python -m pip install -e ".[performance]"
```

The extras stay optional so the pure-Python reference paths and existing
install remain usable. Keylab selects Coincurve for secp256k1 multiplication
when present, then `fastecdsa`, then its reference implementation. Large RSA
modular powers and integer roots use `gmpy2` when installed. The secure RSA API
in `keylab.crypto` uses `cryptography` with OAEP-SHA256 and PSS-SHA256; install
`keylab[crypto-alt]` to use PyCryptodome as an alternative backend. Coincurve
is pinned to 19.0.1 for broad Python 3.14 Windows wheel availability: 20.0.0
has no Python 3.14 wheel and its source build currently errors on scikit-build
configuration.

Install the other comparison and research packages with:

```powershell
python -m pip install -e ".[all-backends]"
```

This includes PySAT, PycoSAT, and CDCLKit. For a certified CDCLKit command-line
run, use `python -m cdclkit solve formula.cnf --self-check --check-model`.
Native solver availability depends on the selected package and platform.

Use `keylab backends` to see what is installed. To solve a DIMACS file through
an in-process binding, run:

```powershell
keylab sat-solve --input formula.cnf --backend auto
```

Automatic SAT dispatch prefers PySAT, then the existing CryptoMiniSat binding,
then PycoSAT. PySAT's solver can be selected with `--solver-name` (for example,
`cadical195`). The built-in SAT/CNF encoders and external solver support remain
available for benchmarking and reproducible research. Actual performance
depends on the workload, Python build, native wheels, and machine; benchmark
results should be measured locally rather than assumed from another system.
