from dataclasses import dataclass

from .merkletree import MerkleTree


@dataclass
class Contribution:
    user_id: str
    type: str
    content: str


@dataclass
class Block:
    id: int
    merkle_tree: MerkleTree
    contributions: list[Contribution]
