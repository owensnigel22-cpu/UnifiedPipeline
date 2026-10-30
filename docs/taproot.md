# Taproot (BIP-341 / BIP-86)

Modules: `keylab.encoding.taproot`, `keylab.encoding.transaction`.

## Outputs and script trees

```python
from keylab.encoding.taproot import TapLeaf, build_script_tree, taproot_script_tree_output

tree = [TapLeaf(script_a), [TapLeaf(script_b), TapLeaf(script_c, 0xFA)]]
output, control_blocks = taproot_script_tree_output(internal_key_x, tree)
built = build_script_tree(tree)     # merkle_root, and per-leaf (leaf_hash, merkle_path)
```

- A tree is a `TapLeaf` or a pair `(left, right)`; this mirrors BIP-341's
  reference `taproot_tree_helper`, and leaves are reported depth-first,
  left to right.
- `taproot_output` / `taproot_output_from_point` compute `Q = P + tG` with
  `t = hash_TapTweak(P_x ‖ root)`; key-path-only outputs use an empty root.
- `verify_taproot_script_path` checks that a control block commits a script
  to an output key. It does **not** execute the script.

## Key-path spending

```python
from keylab.encoding.transaction import TxOut, parse_transaction, taproot_sighash
from keylab.encoding.taproot import taproot_sign_key_path

tx = parse_transaction(raw_unsigned_tx)
sighash = taproot_sighash(tx, input_index, spent_outputs, hash_type)
witness_sig = taproot_sign_key_path(sighash, internal_secret, merkle_root, hash_type=hash_type)
```

- `taproot_tweak_seckey(d, root)` negates `d` if its point has odd y, then
  adds the tweak, so the result signs for the output key `Q`.
- Signatures are 64 bytes for `SIGHASH_DEFAULT` (0x00) and 65 bytes
  (hash type appended) otherwise.

## Signature message (sighash)

`taproot_signature_message` returns `0x00 ‖ SigMsg(hash_type, ext_flag)` and
`taproot_sighash` returns `hash_TapSighash` of it. Supported:

- all hash types: `0x00`, `0x01`, `0x02`, `0x03`, `0x81`, `0x82`, `0x83`
- `ANYONECANPAY`, `NONE`, `SINGLE` (raises if there is no matching output)
- the annex (must start with `0x50`)
- the BIP-342 script-path extension (`leaf_hash`, key version 0, `codesep_pos`)

`taproot_precomputed_hashes` exposes `hashPrevouts`, `hashAmounts`,
`hashScriptPubkeys`, `hashSequences`, and `hashOutputs`.

## Test coverage

`tests/test_taproot_bip341.py` runs the full official
`wallet-test-vectors.json`: all 7 scriptPubKey cases (tweaks, Merkle roots,
leaf hashes, control blocks, addresses) and all 7 key-path inputs (internal
key, tweak, tweaked secret, sigMsg, sigHash, and the exact witness signature
across hash types 0x00-0x83). BIP-86 vectors are in
`tests/test_bip32_vectors.py`.

## Limitations

- No script execution, consensus validation, or transaction construction.
- No PSBT (BIP-174/371) support.
- Script-path *signing* is not wrapped; compute the script-path sighash with
  `leaf_hash=` and sign with `schnorr_sign` using the untweaked key.
