"""
Alice - Decentralized AI Training Network
"""

from .model import (
    AliceConfig,
    AliceModel,
    AliceForCausalLM,
    create_alice_7b,
)

__version__ = "0.1.0"
__all__ = [
    "AliceConfig",
    "AliceModel", 
    "AliceForCausalLM",
    "create_alice_7b",
]
