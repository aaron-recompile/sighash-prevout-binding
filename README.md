# sighash-prevout-binding

Taproot-native input binding on Bitcoin Inquisition signet: a tapscript that lets UTXO A be
spent **only if a specific UTXO B is spent in the same transaction**, using `OP_CAT` (BIP 347)
and `OP_CHECKSIGFROMSTACK` (BIP 348). Two confirmed transactions, plus a keyless verifier that
re-checks every claim from public block-explorer data.

Context: this answers the input-binding question in Robin Linus's Delving thread
[How CTV+CSFS improves BitVM bridges](https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591)
(question in [#28](https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/28),
on-chain evidence in [#29](https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/29)).
Fuller write-up: [Taproot-native prevout binding via sighash preimage decomposition](https://delvingbitcoin.org/t/taproot-native-prevout-binding-via-sighash-preimage-decomposition/2483).

## The problem

The bridge construction needs "inputA is spendable only together with inputB". The original
proposal had CTV commit to inputB's legacy `scriptSig`. ajtowns pointed out
([#8](https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8)) that this binds
to scriptSig *bytes*, not to the UTXO: any other UTXO whose script accepts the same scriptSig can
be substituted for B. Here the binding target is instead `sha_prevouts`, the BIP-341 digest of the
transaction's input outpoints, which the signature already commits to.

## Construction

Two building blocks:

1. **Same-signature binding.** One 64-byte Schnorr signature must pass both
   `OP_CHECKSIGFROMSTACK` (over a message the witness supplies) and `OP_CHECKSIG` (over the
   sighash the node computes from the real transaction). Passing both means the witness-supplied
   preimage is the real one; otherwise a hash collision would be required. This does not rely on
   the spender being unable to sign: the key holder can sign anything, but cannot make one
   signature stand for two different messages.
2. **Preimage decomposition.** The tapscript signature message (epoch byte + BIP-341 SigMsg +
   BIP-342 extension) is 212 bytes and field-aligned for `SIGHASH_DEFAULT` without annex.
   `sha_prevouts` is bytes 10..41. The witness supplies the preimage in chunks, so the script can
   inspect one chunk before reassembling the whole with `OP_CAT`.

The 196-byte leaf of A hardcodes **B's outpoint** (36 bytes). The witness supplies **A's
outpoint**. The script checks `SHA256(A_outpoint || B_outpoint) == sha_chunk`, then reassembles
and binds the preimage:

```
witness (bottom -> top): sig(64) post_c(56) post_b(57) post_a(57) pre(10) sha(32) a_outpoint(36)

<B_outpoint> CAT SHA256 SWAP DUP ROT EQUALVERIFY   # sha == SHA256(a_outpoint || B)
SWAP SIZE 10 EQUALVERIFY                            # pre is 10 bytes -> sha sits at offset 10
SWAP CAT SWAP CAT SWAP CAT SWAP CAT                 # pre||sha||post_a||post_b||post_c
<tag[0:32]> <tag[32:64]> CAT SWAP CAT SHA256        # TapSighash(preimage)
OVER SWAP <pk> CHECKSIGFROMSTACK VERIFY             # sig valid over witness preimage
<pk> CHECKSIG                                       # same sig valid over real sighash
```

Every witness item is < 80 bytes (Inquisition relay policy rejects larger items).

Why substitution fails: if A is spent with C instead of B, the real `sha_prevouts` is
`SHA256(A || C)`. Supplying it fails the `EQUALVERIFY` against `SHA256(A || B)`; supplying
`SHA256(A || B)` instead makes the witness preimage differ from the real one, so the same
signature cannot pass both CSFS and CHECKSIG. ajtowns' attack on the scriptSig path does not
apply because nothing here depends on a byte pattern in another input's script.

## On-chain results (Inquisition signet)

| Case | Result |
|------|--------|
| A + B, round 1 | confirmed, block 300156: [`b7959a71...304606`](https://mempool.space/signet/tx/b7959a71b74b8bbed69d52c22a9b3b90af176391be2d0b7f33eb1a6473304606) |
| A + B, round 2 (fresh A and B) | confirmed, block 300156: [`7311da6e...a83558`](https://mempool.space/signet/tx/7311da6e30886fab6594b633bcb97e4436d49f02ecc244d4bc7c59cb1ea83558) |
| A + C (C substituted for B) | rejected by `testmempoolaccept`: `Script failed an OP_EQUALVERIFY operation` (never broadcast, so not on chain) |

## Verify without a node or keys

```bash
python3 verify_onchain.py
```

Standard library only. For each confirmed spend it fetches `/tx/<txid>` and `/tx/<txid>/hex` from
the mempool.space signet API and checks: 2 inputs; raw hex hashes to the txid; 196-byte leaf;
the leaf hardcodes input 1's outpoint and the witness carries input 0's outpoint;
`SHA256(outpoint_A || outpoint_B)` recomputed from the actual inputs equals the `sha_prevouts`
witness item; the reassembled 212-byte witness preimage is byte-identical to the BIP-341/342
SigMsg recomputed independently from the transaction; the signature is a valid BIP-340 signature
over `TapSighash(preimage)` for the key in the leaf; and the leaf is committed in the spent
output's Taproot key. Current result: 30/30 PASS.

## Reproduce

Requires a synced Bitcoin Inquisition signet node with a funded wallet, Python 3.10-3.12, and
`libsecp256k1` (for the `secp256k1` Python binding).

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp env.example .env        # then fill in values; .env is gitignored
python3 exp_sighash_prevout_binding_chunked.py --fund     # funds B, then A (A's leaf embeds B)
python3 exp_sighash_prevout_binding_chunked.py --spend    # A + B, testmempoolaccept then broadcast
python3 exp_sighash_prevout_binding_chunked.py --fund
python3 exp_sighash_prevout_binding_chunked.py --attack   # A + C, testmempoolaccept only
```

`CAT_DEMO_WIF` is the signet key used for A's internal key and for the leaf's CSFS/CHECKSIG key.
State between steps is kept in `.prevout_binding_chunked_state.json` (gitignored).

## Files

`exp_sighash_prevout_binding_chunked.py` is the fund / spend / attack script that produced the
transactions above (it rebuilds the exact on-chain 196-byte leaf). Helpers: `opcodes.py` (opcode
constants, script builder), `config.py` (`bitcoin-cli` RPC), `template_common.py` (funding,
UTXO lookup, broadcast), `load_local_env.py` (optional `.env`). `verify_onchain.py` is standalone.

## Scope and limitations

- Signet experiment, not a bridge implementation. `OP_CAT` and `OP_CHECKSIGFROMSTACK` are active on
  Inquisition signet only.
- The leaf fixes the whole input set: exactly two inputs, A at index 0 and B at index 1. B's
  outpoint must exist before A's address can be derived.
- The script assumes `SIGHASH_DEFAULT`, no annex, script-path spend (fixed 212-byte layout). Only
  the first chunk is size-locked; the post chunks are pinned by the same-signature check.
- A spend still needs a signature from the leaf key; how that key is held (presigned, shared,
  aggregated) is out of scope here.
- Cost: 754-byte transaction (290 vB) for the round-1 spend, versus one opcode for a dedicated
  introspection primitive. The point is that the capability exists with CAT + CSFS, not efficiency.

## Credits

Built with [btcaaron](https://github.com/aaron-recompile/btcaaron) (Taproot tree and spend
builder). An earlier copy of the script lives in
[inquisition-experiments](https://github.com/aaron-recompile/inquisition-experiments/blob/91ca2fcee64d81e066d5cb645ae84dbd7bb27870/experiments/exp_sighash_prevout_binding_chunked.py).

MIT License.
