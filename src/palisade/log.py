"""The checkpointed replicated log: validators, records, and epochs.

This wires the pieces into the primitive of Definitions 1-2: a history tree of
schema-checked records, epochs closed by quorum-signed checkpoint certificates,
and a portable checkpoint chain. The BFT commit core itself is textbook
(PBFT/Tendermint) and out of scope for this reference build; what is
implemented here is the accountable surface -- schema validation, the history
tree, checkpoint co-signing under stateful hash keys, and on-log index
disclosure -- which is where PALISADE's novelty and its hazards live.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from .checkpoint import (
    CheckpointBody,
    CheckpointCertificate,
    GENESIS_PREV,
    ValidatorRegistry,
    ValidatorSignature,
)
from .merkle import ConsistencyProof, HistoryTree, InclusionProof
from .records import schema_valid
from .signatures import HardwareModule, HashSignature


def quorum_size(n: int, f: int) -> int:
    """Checkpoint quorum |Sigma| >= 2f+1 (Definition 2)."""
    if n < 3 * f + 1:
        raise ValueError(f"need n >= 3f+1; got n={n}, f={f}")
    return 2 * f + 1


class Validator:
    """A registered validator with a stateful hardware signing module.

    The validator signs checkpoint bodies via :meth:`sign`, which drives the
    module's ``sign_next`` (K1: atomic sign-and-increment). The consumed OTS
    index rides on-log in the returned signature (K3).
    """

    def __init__(self, validator_id: str, module: HardwareModule) -> None:
        self.id = validator_id
        self._module = module

    @property
    def public_key(self) -> bytes:
        return self._module.public_key

    @property
    def next_index(self) -> int:
        return self._module.next_index

    def sign(self, message: bytes) -> HashSignature:
        return self._module.sign_next(message)

    def sign_checkpoint(self, body: CheckpointBody) -> ValidatorSignature:
        return ValidatorSignature(self.id, self.sign(body.canonical()))


@dataclass
class PalisadeLog:
    """A single committed log instance with epoch checkpointing.

    In the honest path all correct validators drive an identical instance; this
    class models that shared committed state and the checkpoint it emits.
    """

    n: int
    f: int
    registry: ValidatorRegistry
    tree: HistoryTree = field(default_factory=HistoryTree)
    epoch: int = 0
    prev_cp_hash: bytes = GENESIS_PREV
    chain: List[CheckpointCertificate] = field(default_factory=list)

    @property
    def quorum(self) -> int:
        return quorum_size(self.n, self.f)

    @property
    def size(self) -> int:
        return self.tree.size

    def append_record(self, record) -> int:
        """Schema-check then append a record's canonical bytes (Alg. 1 line 1).

        Raises ``ValueError`` if the record fails the fixed schema check -- the
        log has no virtual machine and no contract layer, only this gate.
        """
        if not schema_valid(record):
            raise ValueError("record failed schema validation")
        return self.tree.append(record.canonical())

    def root(self) -> bytes:
        return self.tree.root()

    def build_checkpoint_body(self) -> CheckpointBody:
        return CheckpointBody(
            epoch=self.epoch,
            root=self.tree.root(),
            size=self.tree.size,
            prev_hash=self.prev_cp_hash,
        )

    def checkpoint(self, validators: Sequence[Validator]) -> CheckpointCertificate:
        """Close the current epoch: collect >= 2f+1 validator signatures over
        the checkpoint body, assemble the certificate, and advance the chain."""
        body = self.build_checkpoint_body()
        signatures = [v.sign_checkpoint(body) for v in validators]
        cert = CheckpointCertificate(body=body, signatures=signatures)
        if not cert.verify(self.registry, self.quorum):
            raise ValueError("assembled checkpoint does not meet quorum")
        self.chain.append(cert)
        self.prev_cp_hash = cert.cert_hash()
        self.epoch += 1
        return cert

    def inclusion_proof(self, index: int, size: Optional[int] = None) -> InclusionProof:
        return self.tree.inclusion_proof(index, size)

    def consistency_proof(self, first_size: int, second_size: Optional[int] = None) -> ConsistencyProof:
        return self.tree.consistency_proof(first_size, second_size)
