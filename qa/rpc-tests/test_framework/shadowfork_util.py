#!/usr/bin/env python3
# Copyright (c) 2025 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Shadow fork test utilities.

Provides helpers for creating transactions with sentinel signatures that bypass
CHECKSIG verification in shadow fork mode.

Sentinel signature format: 30 06 02 01 01 02 01 01 [hashtype]
This is a minimal DER-encoded signature with r=1, s=1.
"""

import json
import os

from .script import (
    CScript,
    OP_0,
    OP_1,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
    OP_CHECKMULTISIG,
    OP_EQUAL,
    hash160,
)
from .mininode import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
    ToHex,
    COIN,
)


# Sentinel signature bytes (DER-encoded r=1, s=1)
SENTINEL_SIG_DER = bytes.fromhex("3006020101020101")


def sentinel_signature(hashtype=0x01):
    """Return sentinel signature with hashtype appended.

    Args:
        hashtype: SIGHASH type (default: SIGHASH_ALL = 0x01)

    Returns:
        bytes: Sentinel signature with hashtype byte appended
    """
    return SENTINEL_SIG_DER + bytes([hashtype])


def create_p2pkh_script_pubkey(pubkey_bytes):
    """Create a P2PKH scriptPubKey.

    Args:
        pubkey_bytes: Compressed or uncompressed public key bytes

    Returns:
        CScript: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    pubkey_hash = hash160(pubkey_bytes)
    return CScript([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])


def create_p2pkh_scriptsig(pubkey_bytes, hashtype=0x01):
    """Create a P2PKH scriptSig with sentinel signature.

    Args:
        pubkey_bytes: Public key bytes
        hashtype: SIGHASH type (default: SIGHASH_ALL)

    Returns:
        CScript: <sentinel_sig> <pubkey>
    """
    sig = sentinel_signature(hashtype)
    return CScript([sig, pubkey_bytes])


def create_p2sh_script_pubkey(redeem_script):
    """Create a P2SH scriptPubKey from a redeem script.

    Args:
        redeem_script: The redeem script (CScript)

    Returns:
        CScript: OP_HASH160 <script_hash> OP_EQUAL
    """
    script_hash = hash160(redeem_script)
    return CScript([OP_HASH160, script_hash, OP_EQUAL])


def create_p2sh_scriptsig(redeem_script, inner_data):
    """Create a P2SH scriptSig.

    Args:
        redeem_script: The redeem script (CScript)
        inner_data: List of data items to push before redeem script

    Returns:
        CScript: <inner_data...> <serialized_redeem_script>
    """
    return CScript(inner_data + [redeem_script])


def create_multisig_script_pubkey(m, pubkeys):
    """Create a bare m-of-n multisig scriptPubKey.

    Args:
        m: Number of required signatures
        pubkeys: List of public key bytes

    Returns:
        CScript: OP_m <pubkey1> <pubkey2> ... OP_n OP_CHECKMULTISIG
    """
    n = len(pubkeys)
    if m < 1 or m > n or n > 16:
        raise ValueError(f"Invalid multisig params: {m}-of-{n}")

    return CScript([m] + pubkeys + [n, OP_CHECKMULTISIG])


def create_multisig_scriptsig(m, hashtype=0x01):
    """Create a multisig scriptSig with sentinel signatures.

    Args:
        m: Number of signatures required
        hashtype: SIGHASH type (default: SIGHASH_ALL)

    Returns:
        CScript: OP_0 <sig1> <sig2> ... (m signatures)

    Note: OP_0 is the dummy element for CHECKMULTISIG off-by-one bug.
    """
    sig = sentinel_signature(hashtype)
    # OP_0 is the dummy for CHECKMULTISIG bug, then m sentinel signatures
    script_parts = [OP_0] + [sig] * m
    return CScript(script_parts)


def create_p2sh_multisig_scriptsig(m, redeem_script, hashtype=0x01):
    """Create a P2SH multisig scriptSig with sentinel signatures.

    Args:
        m: Number of signatures required
        redeem_script: The multisig redeem script
        hashtype: SIGHASH type (default: SIGHASH_ALL)

    Returns:
        CScript: OP_0 <sig1> <sig2> ... <serialized_redeem_script>
    """
    sig = sentinel_signature(hashtype)
    # OP_0 + m signatures + serialized redeem script
    script_parts = [OP_0] + [sig] * m + [redeem_script]
    return CScript(script_parts)


def create_funding_tx(node, script_pubkey, amount_satoshi):
    """Create a UTXO with arbitrary scriptPubKey using RPC.

    Args:
        node: RPC node connection (from test framework)
        script_pubkey: CScript or bytes for the output scriptPubKey
        amount_satoshi: Amount in satoshis

    Returns:
        tuple: (txid_hex, vout_index, amount_satoshi)
    """
    utxos = node.listunspent(1)
    if not utxos:
        raise RuntimeError("No spendable UTXOs available")

    # Select a UTXO large enough to cover amount + fee
    # Fee is 1 DOGE, so minimum required is amount_satoshi + COIN
    min_required = amount_satoshi + COIN
    utxo = None
    for u in sorted(utxos, key=lambda x: x['amount'], reverse=True):
        if int(u['amount'] * COIN) >= min_required:
            utxo = u
            break

    if utxo is None:
        raise RuntimeError(f"No UTXO large enough (need {min_required/COIN} DOGE, "
                          f"max available: {max(u['amount'] for u in utxos)})")

    utxo_amount = int(utxo['amount'] * COIN)

    # Build the transaction
    tx = CTransaction()
    tx.vin.append(CTxIn(
        COutPoint(int(utxo['txid'], 16), utxo['vout']),
        b"",
        0xffffffff
    ))

    # Output with desired scriptPubKey
    spk = bytes(script_pubkey) if isinstance(script_pubkey, CScript) else script_pubkey
    tx.vout.append(CTxOut(amount_satoshi, spk))

    # Change output (fee: 1 DOGE - Dogecoin has higher fee requirements)
    fee = 1 * COIN
    change_amount = utxo_amount - amount_satoshi - fee
    if change_amount > 0:
        change_addr = node.getnewaddress()
        change_script = bytes.fromhex(node.validateaddress(change_addr)['scriptPubKey'])
        tx.vout.append(CTxOut(change_amount, change_script))

    # Sign and send
    signed = node.signrawtransaction(ToHex(tx))
    if not signed.get('complete', False):
        raise RuntimeError(f"Failed to sign funding tx: {signed.get('errors', [])}")

    return (node.sendrawtransaction(signed['hex']), 0, amount_satoshi)


def _build_script_sig(script_type, pubkey, m, redeem_script):
    """Build scriptSig for the given script type."""
    if script_type == 'p2pkh':
        if pubkey is None:
            raise ValueError("pubkey required for p2pkh")
        return create_p2pkh_scriptsig(pubkey)

    if script_type == 'p2sh-p2pkh':
        if pubkey is None or redeem_script is None:
            raise ValueError("pubkey and redeem_script required for p2sh-p2pkh")
        return create_p2sh_scriptsig(redeem_script, [sentinel_signature(), pubkey])

    if script_type == 'multisig':
        if m is None:
            raise ValueError("m required for multisig")
        return create_multisig_scriptsig(m)

    if script_type == 'p2sh-multisig':
        if m is None or redeem_script is None:
            raise ValueError("m and redeem_script required for p2sh-multisig")
        return create_p2sh_multisig_scriptsig(m, redeem_script)

    raise ValueError(f"Unknown script_type: {script_type}")


def build_sentinel_spend_tx(utxo_txid, utxo_vout, utxo_amount,
                            script_type, pubkey=None, pubkeys=None,
                            m=None, redeem_script=None, output_script=None,
                            fee=100000000):  # 1 DOGE fee to pass priority checks
    """Build a transaction spending a UTXO with sentinel signature.

    Args:
        utxo_txid: Txid (hex string) of the UTXO to spend
        utxo_vout: Vout index of the UTXO
        utxo_amount: Amount in satoshis
        script_type: One of 'p2pkh', 'p2sh-p2pkh', 'multisig', 'p2sh-multisig'
        pubkey: Public key bytes (for p2pkh, p2sh-p2pkh)
        pubkeys: List of public key bytes (for multisig)
        m: Number of signatures required (for multisig)
        redeem_script: Redeem script for P2SH types
        output_script: Output scriptPubKey (CScript or bytes)
        fee: Transaction fee in satoshis

    Returns:
        CTransaction: The signed transaction
    """
    tx = CTransaction()
    tx.vin.append(CTxIn(
        COutPoint(int(utxo_txid, 16), utxo_vout),
        b"",
        0xffffffff
    ))

    # Output (default to OP_TRUE if not specified)
    if output_script is None:
        output_script = CScript([OP_1])
    out_bytes = bytes(output_script) if isinstance(output_script, CScript) else output_script
    tx.vout.append(CTxOut(utxo_amount - fee, out_bytes))

    tx.vin[0].scriptSig = bytes(_build_script_sig(script_type, pubkey, m, redeem_script))
    tx.calc_sha256()

    return tx


def load_snapshot(filename="shadowfork_snapshot.json"):
    """Load pinned snapshot data from qa/rpc-tests/data/.

    Args:
        filename: Name of the snapshot JSON file

    Returns:
        dict: Snapshot data containing pinned_height, blocks, known_spendable_utxo
    """
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    filepath = os.path.join(data_dir, filename)
    with open(filepath, 'r') as f:
        return json.load(f)
