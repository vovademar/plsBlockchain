from hashlib import sha256


class MerkleTree:
    def __init__(self, leaves, is_from_hashes=False):
        """
        Initialize the Merkle tree with the given leaves, where each leaf is a tuple of (user_id, data).
        :param leaves: List of (user_id, data) tuples, where each element is a leaf of the tree.
        """
        if is_from_hashes:
            self.create_tree_with_hashes(leaves)
        else:
            self.leaves = leaves
            self.leaves.sort(key=lambda x: x[0])
            self.renumbered_ids = {}
            for i, leaf in enumerate(leaves):
                leaves[i] = (i, leaf[1])
                self.renumbered_ids[leaf[0]] = i
            if len(leaves) % 2 != 0:
                self.leaves.append(self.leaves[-1])
            self.tree = []
            self.create_tree()
    
    def to_json(self):
        return {
            "MerkleTree"
        }

    def create_tree(self):
        """
        Creates the Merkle tree by repeatedly combining the hashes of pairs
        of leaves until only a single root hash remains.
        """
        # Create a copy of the list of leaves, so that the original list is not modified
        leaves = list(self.leaves)

        # Create the bottom level of the tree
        for user_id, data in leaves:
            leaf = (user_id, self.get_leaf_hash(data))
            self.tree.append(leaf)

        # Repeatedly combine the hashes of pairs of nodes until only a single root hash remains
        while len(self.tree) > 1:
            new_tree = []
            for i in range(0, len(self.tree) - 1, 2):
                new_tree.append(self.get_parent_hash(self.tree[i], self.tree[i + 1]))
            self.tree = new_tree
            
    def create_tree_from_merkle_path(self, path, leaf_hash):
        hashes = []
        skip = False
        for sibling_hash, direction in path:
            if direction == 'left':
                hashes.append((None, sibling_hash))
            else:
                if not skip:
                    hashes.append((None, leaf_hash))
                    skip = True
                hashes.append((None, sibling_hash))
            leaf = self.get_parent_hash(hashes[-2], hashes[-1])
        self.tree = [(None, hash_value) for hash_value in hashes]
        while len(self.tree) > 1:
            new_tree = []
            for i in range(0, len(self.tree) - 1, 2):
                new_tree.append(self.get_parent_hash(self.tree[i], self.tree[i + 1]))
            self.tree = new_tree

    def get_leaf_hash(self, leaf):
        """
        Compute the hash of a leaf node.
        :param leaf: data bytes
        :return: bytes
        """
        return sha256(leaf).digest()
    
    def get_parent_hash(self, left, right):
        """
        Compute the hash of a parent node, given the hashes of its left and right children.
        :param left: tuple
        :param right: tuple
        :return: bytes
        """
        parent_hash = sha256(left[1] + right[1]).digest()
        return (None, parent_hash)
        
    def get_merkle_path(self, user_id):
        """
        Get the Merkle Path for a given leaf.
        :param user_id: The user_id of the leaf for which the Merkle Path is needed.
        :return: List of tuples (sibling_hash, direction), where direction is 'left' or 'right'
        """
        user_id = self.renumbered_ids[user_id]
        print(user_id)
        # Find the index of the leaf with the given user_id
        leaf_index = None
        for i, leaf in enumerate(self.leaves):
            if leaf[0] == user_id:
                leaf_index = i
                break

        if leaf_index is None:
            raise ValueError("Leaf with user_id not found")

        path = []
        tree_level = [self.get_leaf_hash(leaf[1]) for leaf in self.leaves]

        sibling_index = None

        while len(tree_level) > 1:
            sibling_index = leaf_index - 1 if leaf_index % 2 == 1 else leaf_index + 1
            direction = 'left' if sibling_index < leaf_index else 'right'
            path.append((tree_level[sibling_index], direction))

            # Move up to the parent level
            tree_level = [sha256(tree_level[i] + tree_level[i + 1]).digest() for i in range(0, len(tree_level) - 1, 2)]
            leaf_index = leaf_index // 2

        return path
    
    def print_tree(self):
        print("1. in print tree")
        """
        Print the entire Merkle tree.
        """
        tree_level = [self.get_leaf_hash(leaf[1]) for leaf in self.leaves]
        levels = [tree_level]

        # Compute all levels of the tree
        while len(tree_level) > 1:
            print("2. computing")
            tree_level = [sha256(tree_level[i] + tree_level[i + 1]).digest() for i in range(0, len(tree_level) - 1, 2)]
            levels.append(tree_level)

        print("before printing")
        # Print the tree, level by level
        for level_num, level in enumerate(levels, 1):
            print(f"Level {level_num}:")
            for node_hash in level:
                print(f"  {node_hash.hex()}")
            print()

    @property
    def root_hash(self):
        """
        Get the root hash of the Merkle tree.
        :return: bytes
        """
        return self.tree[0][1]
    
    @property
    def root_hash_str(self):
        """
        Get the root hash of the Merkle tree.
        :return: bytes
        """
        return self.tree[0][1].hex()


if __name__ == "__main__":
    # Example
    leaves = [(41, b"Hello"), (28, b"World"), (32, b"!")]
    merkle_tree = MerkleTree(leaves)
    print("Root hash:", merkle_tree.root_hash.hex())
    print("User ID:", merkle_tree.leaves[0][0])

    user_id = 32
    merkle_path = merkle_tree.get_merkle_path(user_id)
    print(f"Merkle Path for user_id {user_id}:")
    for sibling_hash, direction in merkle_path:
        print(f"{direction}: {sibling_hash.hex()}")

    print("Merkle Tree:")
    merkle_tree.print_tree()
