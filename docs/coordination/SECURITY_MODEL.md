# Security Model

This is a coordination summary of the project's current `SECURITY.md`, `docs/architecture.md`, and `docs/crypto_policy.md`; those files remain authoritative for detailed scope. This document makes no new security guarantee.

## Assumptions and Intended Use

Keylab is research and teaching software. It aims to be readable and checkable against published standards and test vectors. It is not production wallet software, not a consensus implementation, and not independently audited. Do not use it to create or protect keys controlling real value. Intended safe data are published vectors, synthetic fixtures, seeded public benchmark corpora, and throwaway experimental keys on a machine the user controls.

The implemented protocols rely on their published assumptions; Keylab adds and proves none of them. Refer to `docs/architecture.md` for its stated cryptographic assumptions and to the relevant BIP/RFC for protocol requirements.

## Cryptographic Components

The repository contains Python implementations and educational tools involving secp256k1, ECDSA, BIP-340 Schnorr, BIP-327 public-key aggregation, BIP-32/39 derivation, Taproot commitments/signature hashes, Bitcoin encodings and transactions, PSBT v0 roles, SAT/hash analysis, and number theory. Exact supported behavior and scope must be established from source, tests, and the relevant specification; the component list is not a certification.

## Timing and Secret Handling

- Python big-integer arithmetic, secret-dependent branches/table indices, and modular inversions are variable-time. The project is not constant-time and is not side-channel hardened.
- There is no general secure-memory erasure, blinding, or comprehensive fault-injection defense. BIP-340 self-verification catches some computation faults only; it is not a complete fault defense.
- A constant-time comparison helper or use of `hmac.compare_digest` does not make surrounding arithmetic constant-time.
- Optional native libraries such as libsecp256k1 through `coincurve` may offer different primitive-level properties. Their presence does not make all application paths, key handling, or end-to-end workflows production-safe.
- Do not print or log user secrets. Do not ask for or commit real private keys, mnemonics, WIFs, or wallet material. CLI flags that reveal private values require deliberate explicit use and must not be used with real keys.

## Known Functional Limitations

`SECURITY.md` documents that Keylab is not safe for real funds. M12 adds an experimental testnet/regtest wallet path with OS-keyring retrieval, descriptor UTXO scanning, bounded coin selection, supported PSBT signing/finalization, node preflight, and guarded broadcast. Mainnet broadcasting is hard-rejected. This is not audited custody or a full transaction lifecycle. Transaction helpers do not execute Bitcoin Script or validate consensus. PSBT handling supports only documented role/script subsets; it does not imply support for all BIP-174/BIP-370 cases. Research demonstrations require explicitly supplied data/assumptions and do not provide unconstrained real-key recovery. Consult source docs for exact supported scope before making changes.

## Security Review Expectations

Changes to cryptographic behavior, secret handling, parsing/validation, signing, key derivation, protocol serialization, or security claims require focused tests against applicable official vectors and negative cases, independent review where appropriate, and explicit project-owner review before integration. Keep APIs bounded, inputs validated, outputs forward-verified where the existing research contract requires it, and resource limits explicit. Report unknowns rather than filling gaps with assumptions.

Report suspected vulnerabilities without including real private keys. Follow `SECURITY.md` for reporting guidance.
