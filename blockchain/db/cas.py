import pickle
from hashlib import sha256

from .block import Block
from .rot import RootOfTrust


class CAS:
    def __init__(self):
        self.blocks: list[Block] = []
        self.unverified_root_of_trusts: list[RootOfTrust] = []
        print("CAS started")
        self.data = {}
        
    def add_data(self, data: str):
        self.data[sha256(data.encode('utf-8')).hexdigest()] = data
        print(sha256(data.encode('utf-8')).hexdigest(), " - sha256")
        
    def get_data(self, data_hash: str):
        if data_hash not in self.data:
            return None
        return self.data[data_hash]
    
    def add_block(self, block: Block):
        self.blocks.append(block)
        
    def add_unverified_root_of_trust(self, root_of_trust: RootOfTrust):
        self.unverified_root_of_trusts.append(root_of_trust)
        
    def get_unverified_root_of_trust(self) -> RootOfTrust:
        if len(self.unverified_root_of_trusts) < 1:
            return None
        root_of_trust = self.unverified_root_of_trusts[0]
        self.unverified_root_of_trusts = self.unverified_root_of_trusts[1:]
        # print(root_of_trust, "ROT")
        return root_of_trust
        
    def get_latest_block(self) -> Block:
        if len(self.blocks) < 1:
            print("last block returned None")
            return None
        return self.blocks[-1]
    
    def get_latest_block_root_hash(self) -> bytes:
        if len(self.blocks) < 1:
            return None
        return self.get_latest_block().root_hash
    
    def get_all_blocks(self) -> list[Block]:
        if len(self.blocks) < 1:
            print("Amount of blocks is zero")
            return None
        return self.blocks

    
    def get_contribution(self, user_id: str, block_number: int):
        print(f"Getting contribution for user {user_id} in block {block_number}")
        block = self.blocks[block_number]
        contribution = None
        merkle_path = None
        for contrib in block.contributions:
            if contrib.user_id == user_id:
                contribution = contrib
        if contribution is None:
            return contribution, merkle_path
        merkle_path = block.merkle_tree.get_merkle_path(user_id)
        return contribution, merkle_path
    
    def save(self, filename: str) -> None:
        """Save the blockchain to a file."""
        class CASToSerialize:
            def __init__(self, block: Block):
                self.blocks = block.blocks
                self.unverified_root_of_trusts = block.unverified_root_of_trusts
                self.data = block.data
        cas_to_serialize = CASToSerialize(self)
            
        with open(filename, "wb") as f:
            pickle.dump(cas_to_serialize, f)

    def load(self, filename: str) -> None:
        """Load the blockchain from a file."""
        with open(filename, "rb") as f:
            serialized_cas = pickle.load(f)
            self.blocks = serialized_cas.blocks
            self.unverified_root_of_trusts = serialized_cas.unverified_root_of_trusts
            self.data = serialized_cas.data
