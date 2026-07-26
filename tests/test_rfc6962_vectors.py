"""External conformance: the published RFC 6962 / Certificate Transparency vectors.

Every other merkle test in this suite checks PALISADE against itself, which
cannot detect a systematic divergence from the standard. These vectors come
from outside the project (the RFC 6962 reference test data used by the
certificate-transparency implementations), so they pin the log layer to the
ecosystem rather than to our own conventions.

This is what licenses the interoperability claim in the README: a PALISADE
history tree is byte-identical to a CT-class log over the same leaves, which
means the checkpoint/accountability layer above it could sit on top of an
existing Trillian- or sigsum-class log instead of replacing it.
"""

import pytest

from palisade.hashing import empty_root
from palisade.merkle import (
    HistoryTree,
    consistency_path,
    inclusion_path,
    merkle_tree_hash,
)

# RFC 6962 reference test inputs (8 leaves, raw pre-leaf-hash bytes).
INPUTS = [
    b"",
    bytes([0x00]),
    bytes([0x10]),
    bytes([0x20, 0x21]),
    bytes([0x30, 0x31]),
    bytes([0x40, 0x41, 0x42, 0x43]),
    bytes([0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]),
    bytes([0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
           0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F]),
]

# MTH(D[n]) for n = 1..8.
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]

EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_empty_tree_matches_rfc6962():
    assert empty_root().hex() == EMPTY_ROOT


@pytest.mark.parametrize("n", range(1, 9))
def test_tree_roots_match_rfc6962(n):
    assert merkle_tree_hash(INPUTS[:n]).hex() == ROOTS[n - 1]


def test_history_tree_roots_match_rfc6962_incrementally():
    """The append-only tree must hit each published root as it grows."""
    tree = HistoryTree()
    for n, leaf in enumerate(INPUTS, start=1):
        tree.append(leaf)
        assert tree.root().hex() == ROOTS[n - 1], f"size {n}"


@pytest.mark.parametrize(
    "index,expected",
    [
        (0, [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ]),
        (5, [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ]),
    ],
)
def test_inclusion_paths_match_rfc6962(index, expected):
    assert [h.hex() for h in inclusion_path(index, INPUTS)] == expected


def test_consistency_path_matches_rfc6962():
    expected = [
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ]
    assert [h.hex() for h in consistency_path(6, INPUTS)] == expected


def test_published_paths_actually_verify():
    """The published paths are not just byte-equal -- they check out."""
    tree = HistoryTree()
    for leaf in INPUTS:
        tree.append(leaf)
    root = tree.root()
    for i in range(8):
        assert tree.inclusion_proof(i).verify(INPUTS[i], root), f"leaf {i}"
    assert tree.consistency_proof(6, 8).verify(tree.root_at(6), root)
