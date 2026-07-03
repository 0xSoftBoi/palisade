"""Shared fixtures: a registered validator set with hardware modules."""

import os
from typing import List, Tuple

import pytest

from palisade.checkpoint import ValidatorRegistry
from palisade.log import Validator
from palisade.signatures import HardwareModule


def make_validators(n: int, height: int = 4) -> Tuple[List[Validator], ValidatorRegistry]:
    registry = ValidatorRegistry()
    validators: List[Validator] = []
    for i in range(n):
        vid = f"validator-{i}"
        module = HardwareModule(os.urandom(32), height=height)
        v = Validator(vid, module)
        registry.register(vid, v.public_key)
        validators.append(v)
    return validators, registry


@pytest.fixture
def validator_set():
    """n=4, f=1 (n >= 3f+1) with capacity-16 keys."""
    return make_validators(4, height=4)
