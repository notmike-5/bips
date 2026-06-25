"""
Simple example of construction for Pay-to-Merkle-Root (P2MR) outputs and control blocks.

Bech32 encoding code is from sipa, and has been tested against the test vectors in BIP-0350:
https://github.com/sipa/bech32/blob/master/ref/python/tests.py
"""

from enum import Enum
from typing import List

import binascii
import hashlib
import json


class Encoding(Enum):
    """enum type to list supported encodings"""

    BECH32 = 1
    BECH32M = 2


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
BECH32_PREFIX = "bc"

MAX_COMPACT_SIZE = 2**64 - 1


#
# Utility Functions
#
def sha256(b: bytes) -> bytes:
    """sha256 hash function"""
    return hashlib.sha256(b).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute the tagged hash of data as per BIP-340"""
    assert isinstance(data, bytes)
    assert isinstance(tag, str) or tag is None
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def h2b(h: str) -> bytes:
    """hex-to-byte converter"""
    return binascii.unhexlify(h)


def b2h(b: bytes) -> str:
    """byte-to-hex converter"""
    return binascii.hexlify(b).decode("ascii")


def s2w(script: str) -> List[int]:
    """Convert a script/witprog hex string to a List[int] of its bytes"""
    return [int(f"{script[i:i + 2]}", 16) for i in range(0, len(script), 2)]


def get_compact_size(n: int = None) -> bytes:
    """Get the compact size byte for given script."""
    if isinstance(n, float) and n.is_integer():
        n = int(n)  # Recover integral float -> int
    if not isinstance(n, int) or not (
        0 <= n and n <= MAX_COMPACT_SIZE
    ):  # max get_compact_size
        raise ValueError(
            "get_compact_size: out of bounds! must be 0 <= n <= 0xffffffffffffffff"
        )

    if n < 0xFD:  # single-byte case when  size < 0xffff
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    else:  # n > 0xffffffff
        return b"\xff" + n.to_bytes(8, "little")


def serialize_varbytes(b: bytes) -> bytes:
    """serialize variably-sized data as: compact-size byte || data bytes"""
    return get_compact_size(len(b)) + b


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None

    return ret


#
# P2MR-specific Functions
#
def tapleaf_hash(tapscript_ver: str = "c0", script: str = None) -> str:
    """hash function for tree leaves"""
    if not script:
        print("Wat? You forgot the script.")
        return None

    leaf = b"".join(
        (bytes.fromhex(tapscript_ver), serialize_varbytes(bytes.fromhex(script)))
    )

    return tagged_hash("TapLeaf", leaf).hex()


def tapbranch_hash(left, right):
    """hash function for tree branches"""
    if left < right:
        return tagged_hash("TapBranch", h2b(left) + h2b(right))
    return tagged_hash("TapBranch", h2b(right) + h2b(left))


def collect_leaf_hashes(tree, hashes=None, debug=False):
    """Recursively collect leaf hashes in order (for verification)."""
    if hashes is None:
        hashes = []

    if isinstance(tree, dict):  # Leaf
        version = f"{tree['leafVersion']:x}"
        script = tree["script"]
        h = tapleaf_hash(tapscript_ver=version, script=script)
        hashes.append(h)
        if debug:
            print(f"{script} => {h}")
    elif isinstance(tree, list):  # Branch: recurse on children
        for sub in tree:
            collect_leaf_hashes(sub, hashes, debug)
    else:
        raise ValueError("Invalid tree node")

    return hashes


def compute_merkle_root(tree):
    """Recursively compute taptree merkle root"""
    if isinstance(tree, dict):  # Leaf
        version = f"{tree['leafVersion']:x}"
        script = tree["script"]
        return tapleaf_hash(tapscript_ver=version, script=script)

    elif isinstance(tree, list):  # Branch
        sub_roots = [compute_merkle_root(sub) for sub in tree]
        root = sub_roots[0]
        for h in sub_roots[1:]:
            root = tapbranch_hash(root, h)
        return root.hex()

    else:  # badbadnotgood
        raise ValueError("Invalid tree node")


def compute_control_block(leaf, tree, path=None):
    """Compute the control block for a given leaf in a given tree"""
    if path is None:
        path = []

    if isinstance(tree, dict):
        if tree == leaf:
            version_byte = (leaf["leafVersion"] | 1) & 0xFF
            return f"{version_byte:02x}" + "".join(path)
        return None

    if isinstance(tree, list):
        for i, child in enumerate(tree):
            # build a list of sibling roots at this level
            siblings = []
            for j, sib in enumerate(tree):
                if j != i:
                    siblings.append(compute_merkle_root(sib))
            # try this child; if it (or a descendant) matches, we get a result
            result = compute_control_block(leaf, child, siblings + path)
            if result:
                return result
    return None


def collect_control_blocks(script_tree):
    """Return control blocks for all leaves in tree declaration order.

    Note: This ordering is for testing purposes. In practice, you would
    compute the control block for a specific leaf at spending time using
    compute_control_block(leaf, tree).
    """
    leaf_nodes = []

    def gather_leaves(node):
        if isinstance(node, dict):
            leaf_nodes.append(node)
        elif isinstance(node, list):
            for sub in node:
                gather_leaves(sub)

    gather_leaves(script_tree)

    control_blocks = []
    for leaf in leaf_nodes:
        cb = compute_control_block(leaf, script_tree)
        if cb:
            control_blocks.append(cb)

    return control_blocks


#
# Bech32/Bech32m Encoding
#
def bech32_polymod(values: list) -> int:
    """compute checksum by taking values mod a (very) large polynomial"""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1

    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0

    return chk


def bech32_hrp_expand(hrp):
    """expand the human readable part for checksum computation"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str = "bc", data=None):
    """verify a Bech32 checksum given hrp and converted data chars"""
    if not data:
        raise ValueError("bech32 data portion must be provided")

    const = bech32_polymod(bech32_hrp_expand(hrp) + data)

    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M

    return None


def bech32_create_checksum(hrp: str = None, data=None, spec=None):
    """create a Bech32 checksum"""
    if not data:
        raise ValueError("bech32 data portion must be provided")

    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const

    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
    """Compute a Bech32 string given hrp and data"""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([BECH32_CHARSET[c] for c in combined])


def bech32_decode(bech):
    """Validate a Bech32/Bech32m string, and determine hrp and data"""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None, None)

    bech = bech.lower()
    pos = bech.rfind("1")

    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)

    if not all(c in BECH32_CHARSET for c in bech[pos + 1 :]):
        return (None, None, None)

    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(c) for c in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if not spec:
        return (None, None, None)

    return (hrp, data[:-6], spec)


def decode(hrp, addr):
    """Decode a SegWit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)

    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)

    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (
        data[0] == 0
        and spec != Encoding.BECH32
        or data[0] != 0
        and spec != Encoding.BECH32M
    ):
        return (None, None)

    return (data[0], decoded)


def encode(hrp, witver, witprog):
    """Encode a SegWit address."""
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)

    if decode(hrp, ret) == (None, None):
        return None

    return ret


#
# BIP-360 Test Code
#
def extract_test_data(v):
    """Extract test data from a test vector, returning None for missing keys."""

    def get_nested(d, *keys):
        for key in keys:
            if not isinstance(d, dict):
                return None
            d = d.get(key)
        return d

    return {
        "id": v["id"],
        "objective": v["objective"],
        "script_tree": get_nested(v, "given", "scriptTree"),
        "leaf_hashes": get_nested(v, "intermediary", "leafHashes"),
        "merkle_root": get_nested(v, "intermediary", "merkleRoot"),
        "script_pubkey": get_nested(v, "expected", "scriptPubKey"),
        "bip350_address": get_nested(v, "expected", "bip350Address"),
        "script_path_control_blocks": get_nested(
            v, "expected", "scriptPathControlBlocks"
        ),
        "error": get_nested(v, "expected", "error"),
        "has_internal_pubkey": "internalPubkey" in v.get("given", {}),
    }


def run_single_test(v, test_num):
    """Run a single test vector. Returns True if passed."""
    print(f"\nBIP-360 Test Vector {test_num}\n{"-" * 25}")

    v = extract_test_data(v)

    # Case 0: P2TR misuse
    if v["has_internal_pubkey"]:
        print("Error: P2MR does not support internal pubkeys")
        return True

    # Case 1: Null tree
    if v["script_tree"] is None:
        assert v["merkle_root"] is None
        assert v["leaf_hashes"] is None
        assert v["script_pubkey"] is None
        print("Null Script Tree")
        print("Error: P2MR requires a script tree with at least one leaf")
        return True

    # Case 2: Single- and Multi-Leaf taptrees
    derived_leaf_hashes = collect_leaf_hashes(v["script_tree"], debug=False)
    assert derived_leaf_hashes == v["leaf_hashes"]
    print("Leaf Hashes: [\n" + ",\n".join(derived_leaf_hashes) + "\n]")

    derived_merkle_root = compute_merkle_root(v["script_tree"])
    assert derived_merkle_root == v["merkle_root"]
    print(f"Merkle Root: {derived_merkle_root}")

    assert f"5220{v['merkle_root']}" == v["script_pubkey"]
    print(f"ScriptPubkey: {v['script_pubkey']}")

    if v["bip350_address"]:
        derived_bip350_address = encode(
            hrp="bc", witver=2, witprog=s2w(derived_merkle_root)
        )
        assert derived_bip350_address == v["bip350_address"]
        print(f"BIP350 Address: {derived_bip350_address}")

    if v["script_path_control_blocks"]:
        derived_script_path_control_blocks = collect_control_blocks(v["script_tree"])
        assert derived_script_path_control_blocks == v["script_path_control_blocks"]
        print(
            "ScriptPathControlBlocks: [\n"
            + ",\n".join(derived_script_path_control_blocks)
            + "\n]"
        )

    if v["error"]:
        print(f"Error: {v['error']}")

    print(f"\nPassed '{v['id']}' with objective '{v['objective']}'")
    return True


def BIP360_tests():
    """Run all BIP-360 Test Vectors"""
    print("\nRunning BIP-0360 Pay-to-Merkle-Root (P2MR) Tests...")

    with open("../common/tests/data/p2mr_construction.json", "r") as f:
        test_vectors = json.load(f)["test_vectors"]

    passed = sum(run_single_test(v, i + 1) for i, v in enumerate(test_vectors))
    print(f"\n{passed}/{len(test_vectors)} BIP-360 tests passed successfully.")


if __name__ == "__main__":
    # a simple, one-leaf tree
    script_tree = {
        "id": 0,
        "script": "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
        "asm": "6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG",
        "leafVersion": 192,
    }

    # generate a regtest address
    address = encode(hrp="tb", witver=2, witprog=s2w(script_tree["script"]))

    # run the BIP360 test vectors
    BIP360_tests()
