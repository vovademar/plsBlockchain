from dataclasses import dataclass


@dataclass
class RootOfTrust:
    block_id: int
    root_hash: str
    total_number_of_users: int
    users_in_block: int
    flags: str
    users: str
    redundancy: str
