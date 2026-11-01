# ECDSA research feature comparison

**Review date:** 2026-11-01  
**Purpose:** Compare publicly documented capabilities as design references for
KeyLab. This is not a security review or endorsement of the tools. Reported
paper results are not promises that KeyLab can reproduce them. Every entry below is a third-party or published claim recorded for design comparison; none is a KeyLab feature or a KeyLab-validated result.

## Feature matrix

| Project | Primary documented capability | Inputs and data | Output / claim | Dependencies and packaging | Important boundary |
|---|---|---|---|---|---|
| [Minerva](https://minerva.crocs.fi.muni.cz/) | CHES 2020 work on noisy leakage of ECDSA nonce bit length, statistical processing, and lattice-based analysis | Repeated ECDSA signatures on known messages plus nonce bit-length leakage or timing-derived observations. The artifacts provide formats for parts of the PoC, including JSON parameters and CSV signature/timing data; these are workflow-specific, not a universal schema. | The project page reports its proposed methods used 500 signatures for simulated leakage, 1,200 for real library data, and 2,100 for smart-card data in the stated experiments. The paper also reports reducing a TPM-Fail dataset requirement from about 40,000 to 900 in its evaluated setup. These are paper results, not general thresholds. | [CROCS repository](https://github.com/crocs-muni/minerva) includes proof-of-concept and measurement/testing artifacts. Project documentation names Python 3, `pyscard`, and `fpylll` for relevant scripts; not a stable, general-purpose package interface. | Paper evaluated several systems/curves; the highlighted smart-card experiment used P-256, not secp256k1. Results depend on the specific leakage, collection quality, and model. The project page explicitly corrects an earlier overbroad EdDSA claim. |
| [TPM-Fail](https://tpm.fail/) | Hardware/firmware ECDSA timing-leakage research against Intel fTPM and STMicroelectronics TPM; timing collection, data analysis, and lattice-based experiments | Device-specific signing/timing measurements and associated signature records. Repository datasets are organized by platforms/setups (`inf`, `intel-root`, `intel-udp`, `intel-strongswan`, `stm`); timing tooling documents a `result.csv` output. Data README describes platform datasets and scripts, not one general interchange schema. | Research paper reports private-key recovery in evaluated TPM settings, including local and remote scenarios. The project site reports 4–20 minutes for the local Intel fTPM scenarios and five hours for its remote VPN demonstration; these are scenario-specific reports, not general performance guarantees. | Research repository contains paper source, data/scripts, and a Linux high-resolution timing tool with kernel/client components; setup is platform- and kernel-sensitive and documents TPM/TSS tooling. It is not a portable Python analysis library. | Device measurement is part of the threat model; collected values are hardware/environment-specific, not interchangeable with synthetic timing. The project documents patched firmware. KeyLab should not include or reproduce device probing. |
| [VUSI](https://github.com/oritwoen/vusi) | Rust ECDSA-signature analysis library/CLI; README advertises nonce-reuse detection and private-key recovery. Optional Cargo features include `polynonce` and `biased-nonce`; the default Cargo feature set is empty. | README documents JSON and CSV signature records containing `r`, `s`, `z`, and optional `pubkey`, plus text or JSON report output. | Its README claims signature analysis and recovery capabilities. This is a repository capability claim; the sources reviewed here do not establish peer-reviewed validation or broad production reliability. | Rust crate with `k256`, `num-bigint`, `num-traits`, `anyhow`, `thiserror`, `clap`, `serde`, `serde_json`, `csv`, and `hex`; optional `rug` for biased-nonce support and optional blockchain integration. | A software project rather than one of the cited side-channel papers. README examples include private-key recovery output. Treat the advertised feature scope as a design comparison, not validated evidence. The reviewed README does not document timing-dataset analysis. |
| [BreakingECDSAwithLLL](https://github.com/daedalus/BreakingECDSAwithLLL) | Python HNP lattice experimentation for biased-nonce ECDSA signatures, with LLL and optional BKZ post-processing; also documents synthetic weak-signature generation | `SPEC.md` documents CSV fields `tx,R,S,Z,pub`, hexadecimal numeric values, and secp256k1 scope. Generator support is an optional extra. | README explicitly exposes private-key candidate recovery, and a synthetic signature generator for demonstration/testing. | Python >=3.11; `olll` and `fpylll` runtime dependencies; optional `ecdsa` generator support; pytest/Hypothesis and lint/type tools as development extras. | Its own specification limits scope to secp256k1 and says parameter tuning is not automatic; it is not a universal lattice solver. It demonstrates an attack workflow rather than a neutral, validated analysis framework. |

## Capability comparison

### Detection versus recovery

- **Minerva and TPM-Fail** are research programs that connect a particular
  source of leakage to statistical processing and lattice analysis. Their
  primary contribution is not a generic signature-file detector; measurement
  conditions and leakage semantics matter.
- **VUSI** documents a signature-oriented CLI/library with nonce-reuse
  detection in its standard interface and optional polynonce/biased-nonce
  Cargo features. Its advertised breadth is not equivalent to independent
  validation of those features.
- **BreakingECDSAwithLLL** focuses on biased nonces and HNP lattice
  construction/reduction, and its documentation makes candidate recovery an
  explicit output.
- None of these sources justifies treating repeated `r`, an observed timing
  difference, or a reduced lattice basis as sufficient evidence by itself.
  KeyLab should separately represent an indicator, a tested mathematical
  relation, and a candidate independently validated against the public key and
  signatures.

### Timing data

- Minerva analyzes nonce-bit-length leakage and discusses simulated,
  software, and smart-card measurements; its released artifacts include
  experiment-specific data and scripts, rather than a universal timing
  schema.
- TPM-Fail contributes device-centered collection tools and datasets tied to
  TPM platforms and setups. Its low-level tooling is materially different
  from offline timing-statistics code.
- The VUSI and BreakingECDSAwithLLL documentation reviewed here is focused on
  signature inputs and nonce analysis, not an end-to-end hardware timing
  collection system.

### Reusable ideas for KeyLab

1. **Keep the leakage model explicit.** Minerva and TPM-Fail show why “biased
   nonce” is not one interchangeable input type: bit-length, timing, and
   known-bit leakage have different semantics and measurement error.
2. **Preserve provenance and setup metadata.** Platform, implementation,
   measurement conditions, units, sample ordering, and data transformations
   affect interpretation.
3. **Separate data acquisition from offline analysis.** KeyLab can model
   validated timing records without providing device drivers, probes, or
   measurement-agent functionality.
4. **Separate detection, hypotheses, basis construction, reduction, and
   forward validation.** This makes each step testable and avoids
   success-shaped claims.
5. **Use a stable schema and explicit parameter record.** The input formats
   in signature-oriented tools and the setup-specific TPM datasets motivate a
   versioned, normalized internal representation with format adapters.
6. **Make synthetic fixtures first-class.** Synthetic weak-data generation
   supports reproducibility and regression tests without collecting real
   device data.
7. **Make optional heavy math dependencies explicit.** Lattice reduction
   stacks should not become hidden, mandatory runtime requirements.
8. **Record failure modes and limits.** Insufficient samples, noise,
   incompatible curves, wrong leakage assumptions, and parameter tuning
   should be visible in structured diagnostics.

## Dependency and data-format implications for KeyLab

Do not copy external schemas or dependencies wholesale. Define KeyLab's own
versioned model and adapters. In particular:

- retain a canonical 32-byte message digest and validated SEC1 public key;
- distinguish digest `z` from a message or transaction identifier;
- document scalar parsing and curve order exactly;
- attach nonce-leak semantics and timing units as typed metadata;
- keep device collection out of scope;
- keep lattice libraries optional, version-recorded, and isolated behind an
  explicit experiment selection;
- never include private-key output as the default result.

The explicit parser and reporting formats for KeyLab are proposed in
[RESEARCH_SUBSYSTEM_ARCHITECTURE.md](RESEARCH_SUBSYSTEM_ARCHITECTURE.md). A
signature-only input schema cannot stand in for measurement provenance or
nonce-leak semantics.

The normative package boundary, report design, safeguards, and staged
implementation are in [RESEARCH_SUBSYSTEM_ARCHITECTURE.md](RESEARCH_SUBSYSTEM_ARCHITECTURE.md),
[SECURITY_POSITIONING.md](SECURITY_POSITIONING.md), and
[IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md).

## Sources

- Minerva project page and CHES 2020 citation:
  [minerva.crocs.fi.muni.cz](https://minerva.crocs.fi.muni.cz/),
  [IACR TCHES DOI 10.13154/tches.v2020.i4.281-308](https://doi.org/10.13154/tches.v2020.i4.281-308),
  [CROCS artifact repository](https://github.com/crocs-muni/minerva).
- TPM-Fail research project:
  [project site](https://tpm.fail/),
  [USENIX Security 2020 paper page](https://www.usenix.org/conference/usenixsecurity20/presentation/moghimi),
  [research repository](https://github.com/vernamlab/TPM-FAIL),
  [data README](https://github.com/vernamlab/TPM-FAIL/blob/master/data/README.md),
  [timing-tool README](https://github.com/vernamlab/TPM-FAIL/blob/master/timing-tool/README.md).
- VUSI:
  [repository README](https://github.com/oritwoen/vusi),
  [Cargo manifest](https://github.com/oritwoen/vusi/blob/main/Cargo.toml),
  [attack modules](https://github.com/oritwoen/vusi/tree/main/src/attack).
- BreakingECDSAwithLLL:
  [repository README](https://github.com/daedalus/BreakingECDSAwithLLL),
  [SPEC.md](https://github.com/daedalus/BreakingECDSAwithLLL/blob/master/SPEC.md),
  [pyproject.toml](https://github.com/daedalus/BreakingECDSAwithLLL/blob/master/pyproject.toml).

Repository documentation and branch state can change. Feature descriptions
above reflect the public pages inspected on the review date; paper results
remain tied to the authors' reported experimental setups.
