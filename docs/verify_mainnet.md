# Read-Only Mainnet Verification

This document describes the current M7 slice. The current implementation fetches transaction bytes through the read-only explorer client and locally verifies BIP-143 signatures for P2WPKH and P2SH-P2WPKH inputs. It does not yet verify block proof-of-work or merkle inclusion, execute Bitcoin Script, or validate consensus.

## Forward-Feed Pipeline

The intended pipeline is:

1. **Fetch:** request raw transaction bytes from an allow-listed public explorer using HTTPS GET.
2. **Parse:** parse the transaction locally with `keylab.encoding.transaction.parse_transaction`.
3. **Supply prevouts:** provide one independently authenticated previous output per transaction input, in input order.
4. **Verify signatures:** reconstruct each supported BIP-143 sighash and verify the ECDSA witness signature and public-key/script relationship locally.
5. **Report:** distinguish fetch/parse failures from invalid or unsupported signatures.

`GET /api/tx/<txid>/merkle-proof` is available for retrieving public proof data, but the current M7 slice does not yet validate that proof against a block header. Fetching a proof is not confirmation verification.

## CLI

Run from the repository root with the project environment active:

```powershell
python scripts/verify_mainnet.py --txid <64-hex-txid> --prevout-data prevouts.json
```

The JSON file contains exactly one prevout record per input, in transaction input order:

```json
{
  "prevouts": [
    {
      "amount_sat": 600000000,
      "script_pubkey": "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
    }
  ]
}
```

Alternatively, pass `--prevout-data -` and pipe that JSON on standard input. The supplied prevouts must be authenticated independently; the CLI does not fetch or authenticate them. A `PASS` means only that every input is supported and its BIP-143 signature verifies against the supplied prevouts. It does not mean that the transaction is confirmed, valid under all consensus rules, or safe to broadcast.

## Explorer Threat Model

The explorer is an untrusted source of transaction/proof bytes, not a verification authority. The client permits HTTPS GET requests to its configured allow-list (default `https://mempool.space`) and enforces TLS 1.2 or newer with certificate validation. It does not transmit private keys or signing payloads. Standard network metadata, including client IP and requested public transaction identifiers, is exposed as expected for HTTPS requests.

Cryptographic checks run locally. Explorer JSON status fields are not treated as proof that a signature or transaction is valid. The currently exposed merkle-proof fetcher only returns data; until local merkle/header checks are implemented, no confirmation claim should be made from its result.

## BIP-143 Prevout Limitation

BIP-143 commits to the spent output's amount and script code. Those values are not generally recoverable from the spending transaction alone. For that reason, signature verification requires caller-supplied prevout data. An incorrect amount or script causes verification to fail, but a matching signature does not establish that the supplied output is the real UTXO being spent.

Obtain prevouts from a source whose relationship to the transaction has been independently authenticated. Do not treat data returned by the same explorer as authenticated solely because it arrived over TLS. Prevout authenticity, full script execution, transaction consensus validity, block proof-of-work, and merkle inclusion are outside this Commit 3/4 slice.

## Live Test

The ordinary pytest configuration excludes network tests. To run the opt-in integration test against a known SegWit transaction served by mempool.space:

```powershell
python -m pytest -m live tests/test_verify_mainnet_live.py
```

The test checks that the returned transaction contains witness data and that its locally computed txid matches the pinned transaction ID. Network availability and the explorer's retention policy can affect this live-only check; mocked tests remain the deterministic default.