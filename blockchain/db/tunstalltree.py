class Node:
    def __init__(self, value=None, left=None, right=None):
        # The value stored at this node
        self.value = value
        # Reference to the left child
        self.left = left
        # Reference to the right child
        self.right = right


class TunstallTree:
    def __init__(self, p, w):
        self.root = Node()
        self.root.left = Node(p)
        self.root.right = Node(1 - p)
        leaf = self.find_maximum_likelihood_leaf(self.root)
        leaf.left = Node(leaf.value * p)
        leaf.right = Node(leaf.value * (1 - p))
        nodes_count = 4
        while nodes_count < 2**w:
            leaf = self.find_maximum_likelihood_leaf(self.root)
            leaf.left = Node(leaf.value * p)
            leaf.right = Node(leaf.value * (1 - p))
            nodes_count += 2
        print("Maximum likelihood leaf value: ", leaf.value)
        self.relabel_leaves(self.root, 0)
        self.create_decoding_table()

    def find_maximum_likelihood_leaf(self, node):
        if not node:
            return None
        if not node.left and not node.right:
            return node
        left_leaf = self.find_maximum_likelihood_leaf(node.left)
        right_leaf = self.find_maximum_likelihood_leaf(node.right)
        if not left_leaf:
            return right_leaf
        if not right_leaf:
            return left_leaf
        if left_leaf.value > right_leaf.value:
            return left_leaf
        return right_leaf

    def relabel_leaves(self, node, leaf_number):
        if not node:
            return leaf_number
        if not node.left and not node.right:
            node.value = leaf_number
            return leaf_number + 1
        leaf_number = self.relabel_leaves(node.left, leaf_number)
        leaf_number = self.relabel_leaves(node.right, leaf_number)
        return leaf_number

    def create_decoding_table(self):
        self.decoding_table = {}
        self.create_decoding_table_rec(self.root, '')
        self.swapped_decoding_table = {value: key for key, value in self.decoding_table.items()}

    def create_decoding_table_rec(self, node, code):
        if not node:
            return
        if not node.left and not node.right:
            self.decoding_table[code] = node.value
            return
        self.create_decoding_table_rec(node.right, code + '0')
        self.create_decoding_table_rec(node.left, code + '1')

    def encode(self, data):
        node = self.root
        encoded = ''
        path = ''
        for bit in data:
            if bit == '0':
                node = node.right
                path += '0'
            else:
                node = node.left
                path += '1'
            if not node.left and not node.right:
                encoded += str(node.value)
                encoded += '.'
                node = self.root
                path = ''
        encoded += ','
        encoded += path
        return encoded
                
    def decode_del(self, data):
        decoded = ''
        keys = data.split('.')
        for key in keys:
            if key == '':
                continue
            elif ',' in key:
                key = key[1:]
                decoded += key
                continue
            print(f"Got key {key} with value {self.swapped_decoding_table[int(key)]}")
            decoded += str(self.swapped_decoding_table[int(key)])
        return decoded

if __name__ == '__main__':
    value = "1011110001111111100000011111110111001111111011001010100101010100110100101010100011111111111111111111111001000101000100111111111110010"
    ones = value.count('1')
    # p = round(ones/ len(value), 2)
    p = 0.6
    w = 4
    tunstall_tree = TunstallTree(p, w)
    print(tunstall_tree.swapped_decoding_table)
    encoded = tunstall_tree.encode(value)
    print(f"Encoded: {encoded}")
    decoded = tunstall_tree.decode_del(encoded)
    print(f"\n\nDecoded: {decoded}")
    print(f"Initial: {value}")