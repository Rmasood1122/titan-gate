"""WO-4.1 AT — offline Rekor inclusion verification (FRD AT-16 first
half: networking disabled, inclusion verifies from bundled proof
against a pinned log key).

RFC 6962 hashing: leaf = SHA-256(0x00 || data), node = SHA-256(0x01 ||
left || right). NOTE: this is REKOR'S domain separation — distinct from
Titan's own 'L|' Merkle prefix. Two trees, two conventions; this module
must implement 6962, not reuse titan merkle code.

Tests build a synthetic 6962 tree in-test (independent implementation
of the same math — the test's tree builder and the module's verifier
agreeing IS the check), then mutate proofs adversarially.

Expected first run: RED (no titan_gate.rekor_inclusion).
"""
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.rekor_inclusion import (
    verify_inclusion_proof,
    verify_checkpoint_signature,
    RekorVerificationError,
)

# --- in-test RFC 6962 tree (independent of module under test) ---

def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()

def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()

def _build_tree(leaves):
    """Returns (root, proofs) where proofs[i] is the audit path for leaf i
    as a list of sibling hashes, leaf-to-root order."""
    n = len(leaves)
    hashes = [_leaf(x) for x in leaves]
    proofs = [[] for _ in range(n)]
    idx = list(range(n))
    level = hashes[:]
    while len(level) > 1:
        nxt, nxt_idx = [], []
        for i in range(0, len(level) - 1, 2):
            parent = _node(level[i], level[i + 1])
            for orig, pos in enumerate(idx):
                if pos == i:
                    proofs[orig].append(level[i + 1])
                elif pos == i + 1:
                    proofs[orig].append(level[i])
            nxt.append(parent)
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        # recompute positions
        new_idx = []
        for pos in idx:
            if pos == len(level) - 1 and len(level) % 2 == 1:
                new_idx.append(len(nxt) - 1)
            else:
                new_idx.append(pos // 2)
        idx = new_idx
        level = nxt
    return level[0], proofs

LEAVES = [f"entry-{i}".encode() for i in range(8)]  # power of 2: clean tree
ROOT8, PROOFS8 = _build_tree(LEAVES)


# --- 1. Honest proofs verify (power-of-two tree, all positions) ---

@pytest.mark.parametrize("i", range(8))
def test_honest_inclusion_all_positions(i):
    verify_inclusion_proof(
        leaf_data=LEAVES[i], leaf_index=i, tree_size=8,
        proof_hashes=PROOFS8[i], expected_root=ROOT8)  # raises on failure


def test_single_leaf_tree():
    root, proofs = _build_tree([b"only"])
    verify_inclusion_proof(leaf_data=b"only", leaf_index=0, tree_size=1,
                           proof_hashes=proofs[0], expected_root=root)


# --- 2. Adversarial mutations all fail ---

def test_wrong_leaf_data_fails():
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=b"forged", leaf_index=3, tree_size=8,
                               proof_hashes=PROOFS8[3], expected_root=ROOT8)

def test_wrong_index_fails():
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=LEAVES[3], leaf_index=4, tree_size=8,
                               proof_hashes=PROOFS8[3], expected_root=ROOT8)

def test_mutated_proof_hash_fails():
    bad = list(PROOFS8[3]); bad[1] = b"\x00" * 32
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=LEAVES[3], leaf_index=3, tree_size=8,
                               proof_hashes=bad, expected_root=ROOT8)

def test_truncated_proof_fails():
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=LEAVES[3], leaf_index=3, tree_size=8,
                               proof_hashes=PROOFS8[3][:-1], expected_root=ROOT8)

def test_wrong_root_fails():
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=LEAVES[3], leaf_index=3, tree_size=8,
                               proof_hashes=PROOFS8[3],
                               expected_root=b"\x11" * 32)

def test_second_preimage_leaf_as_node_fails():
    # Classic 6962 attack shape: feeding an interior node's children as
    # "leaf data" must NOT verify, because leaf hashing is 0x00-domain-
    # separated from node hashing.
    l0, l1 = _leaf(LEAVES[0]), _leaf(LEAVES[1])
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=b"\x01" + l0 + l1, leaf_index=0,
                               tree_size=4,
                               proof_hashes=PROOFS8[0][1:], expected_root=ROOT8)


# --- 3. Checkpoint signature against pinned key ---

_LOG_PRIV = Ed25519PrivateKey.generate()
_LOG_PUB = _LOG_PRIV.public_key()

def _checkpoint_body(origin, size, root_b64_placeholder: bytes) -> bytes:
    import base64
    return (origin.encode() + b"\n" + str(size).encode() + b"\n"
            + base64.b64encode(root_b64_placeholder) + b"\n")

def test_checkpoint_signature_valid():
    body = _checkpoint_body("rekor.sigstore.dev - test", 8, ROOT8)
    sig = _LOG_PRIV.sign(body)
    verify_checkpoint_signature(body, sig, _LOG_PUB)  # raises on failure

def test_checkpoint_signature_wrong_key_fails():
    body = _checkpoint_body("rekor.sigstore.dev - test", 8, ROOT8)
    sig = _LOG_PRIV.sign(body)
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(RekorVerificationError):
        verify_checkpoint_signature(body, sig, other)

def test_checkpoint_tampered_body_fails():
    body = _checkpoint_body("rekor.sigstore.dev - test", 8, ROOT8)
    sig = _LOG_PRIV.sign(body)
    tampered = _checkpoint_body("rekor.sigstore.dev - test", 9, ROOT8)
    with pytest.raises(RekorVerificationError):
        verify_checkpoint_signature(tampered, sig, _LOG_PUB)


# --- 4. Non-power-of-two trees: the promotion branch (flagged gap) ---

@pytest.mark.parametrize("size", range(1, 17))
def test_all_positions_all_sizes_1_to_16(size):
    """Exhaustive: every leaf of every tree size 1-16 verifies. Sizes
    5,6,7,9-15 exercise lone-node promotion at various levels — the
    branch a size-8 tree never touches."""
    leaves = [f"s{size}-e{i}".encode() for i in range(size)]
    root, proofs = _build_tree(leaves)
    for i in range(size):
        verify_inclusion_proof(leaf_data=leaves[i], leaf_index=i,
                               tree_size=size, proof_hashes=proofs[i],
                               expected_root=root)


def test_proof_valid_for_size7_rejected_at_size8():
    """A proof honest for (index, size=7) must not verify with a claimed
    size of 8: size participates in path interpretation, and a verifier
    that ignores it can be steered between tree views."""
    leaves7 = [f"x{i}".encode() for i in range(7)]
    root7, proofs7 = _build_tree(leaves7)
    with pytest.raises(RekorVerificationError):
        verify_inclusion_proof(leaf_data=leaves7[6], leaf_index=6,
                               tree_size=8, proof_hashes=proofs7[6],
                               expected_root=root7)


def test_last_leaf_odd_tree_promotion_path():
    """Size 5, leaf 4: promoted alone through multiple levels — the
    maximal-promotion case, isolated so a failure names itself."""
    leaves = [f"p{i}".encode() for i in range(5)]
    root, proofs = _build_tree(leaves)
    verify_inclusion_proof(leaf_data=leaves[4], leaf_index=4, tree_size=5,
                           proof_hashes=proofs[4], expected_root=root)
    assert len(proofs[4]) == 1  # sibling appears only at the final level
