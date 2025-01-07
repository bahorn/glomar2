"""
Tree structures we use to represent all the blocks used in a stream.

The idea here is we represent the trees intermediate nodes in the space space
in a row header, which the leafs being stored along the rest of the data in the
store.

We can check if we are looking at a leaf or an intermediate node by just
checking if idx % BLOCKS_PER_ROW == 0.

You find the root node of the tree by taking your key and mapping it to an row.


tbh i just need a b-tree?


* id of the root node never maters
* just storing the 16 offsets of children.
* if the child idx % 0 = 0, then its a member of the tree
* else its a leaf.
* we do rely on ordering the nodes.

tbh really just want a tree that fills from left, creating a new parent when
full. that way size can be easily found, and also enable random access.

left balanced tree

partition into blocks of k size each.

then repeat until we have less than k blocks in a step, which becomes the root.

need to determine depth, and find the right most leaf, can determine how many
leaves are in the tree this way.
rightmost path is the only one that shouldn't be full.

block 0xff_ff_ff_ff can't be used.
"""
import math
import struct
from consts import BLOCKS_PER_ROW, USABLE_METADATA_SIZE, TREE_IDX_COUNT
from util import pad
from cryptography.hazmat.primitives import hashes, hmac


def is_leaf(idx):
    """
    Intermediate nodes are stored in the row header, so we know nodes that
    aren't must be leaves.
    """
    return (idx % BLOCKS_PER_ROW) != 0


def valid_idx(idx):
    return idx != 0xff_ff_ff_ff


class TreeNode:
    def __init__(self, idx=None, children=None):
        self._idx = idx
        self._children = []
        if children is None:
            return

        for i in range(0, len(children), 4):
            child_b = children[i * 4: (i + 1) * 4]
            k = struct.unpack('>I', child_b)[0]
            if not valid_idx(k):
                break
            self._children.append(k)

        assert len(self._children) < TREE_IDX_COUNT

    def index(self):
        return self._idx

    def assign(self, idx):
        """
        Assign an idx to this node.
        """
        assert idx % BLOCKS_PER_ROW == 0
        self._idx = idx

    def add_child(self, child):
        """
        Add a child
        """
        assert len(self._children) < TREE_IDX_COUNT
        self._children.append(child)

    def add_children(self, children):
        for child in children:
            self.add_child(child)

    def children(self):
        return self._children

    def __bytes__(self):
        assert self._idx is not None
        res = b''.join(map(lambda x: struct.pack('>I', x), self._children))
        res = pad(res, USABLE_METADATA_SIZE, byte_val=b'\xff')
        assert len(res) == USABLE_METADATA_SIZE
        return res


def get_leaves(store, key, root):
    """
    implementing this recursively for ease. the trees are not deep and we do
    trust them.

    We are doing a depth first search.
    """
    children = root.children()
    leaves = []
    for child in children:
        if is_leaf(child):
            leaves.append(child)
            continue

        possible_row = store.get_row(child)
        possible = possible_row.get_and_decrypt_metadata(key)
        if possible is None:
            raise Exception('child did not decrypt?!')

        leaves += get_leaves(store, key, TreeNode(child, possible))

    return leaves


def store_tree(store, key, leaves, root=0):
    """
    Map the leaves (just indexes) to the store.
    """
    current_layer = leaves

    while len(current_layer) > TREE_IDX_COUNT:
        next_layer = []
        for i in range(0, len(current_layer), TREE_IDX_COUNT):
            row_idx = store.allocate_row()
            real_idx = row_idx * BLOCKS_PER_ROW
            t = TreeNode(real_idx)
            t.add_children(leaves[i * TREE_IDX_COUNT:(i + 1)*TREE_IDX_COUNT])
            next_layer.append(real_idx)
            # store it.
            row_idx = store.allocate_row()
            store.get_row(row_idx).set_and_encrypt_metadata(
                key.tree_key(), bytes(t)
            )

        current_layer = next_layer
    # now create the root.
    t = TreeNode(root)
    t.add_children(current_layer)
    # and save.
    store.get_row(root).set_and_encrypt_metadata(key.root_key(), bytes(t))


class Bitmap:
    """
    A generic bitmap implementation.
    """

    def __init__(self, size, start=0, bitmap=None):
        assert math.log2(size).is_integer()
        self._start = start
        self._size = size
        self._bitmap = list(bitmap) if bitmap else [0] * (self._size // 8)

    def _map_idx(self, idx):
        return idx - self._start

    def set_bit(self, idx):
        assert idx < self._size
        which_byte = self._map_idx(idx) // 8
        which_bit = self._map_idx(idx) % 8
        self._bitmap[which_byte] |= 1 << which_bit

    def set_bits(self, indices):
        for idx in indices:
            self.set_bit(idx)

    def unset_bit(self, idx):
        assert idx < self._size
        which_byte = self._map_idx(idx) // 8
        which_bit = self._map_idx(idx) % 8
        self._bitmap[which_byte] &= 255 ^ (1 << which_bit)

    def is_set(self, idx):
        which_byte = self._map_idx(idx) // 8
        which_bit = self._map_idx(idx) % 8
        res = self._bitmap[which_byte] & (1 << which_bit)
        return res > 0

    def get_offsets(self):
        """
        Get all the set offsets of the set bits in the bitmap.
        """
        return list(filter(
            lambda x: self._start + self.is_set(x),
            range(self._size)
        ))

    def partition(self, size):
        """
        Convert this bitmap into a bunch of smaller ones
        """
        assert self._size % size == 0
        bitmaps = [
            Bitmap(size, start=i, bitmap=self._bitmap[i * size:(i + 1) * size])
            for i in range(0, self._size, size)
        ]
        return bitmaps

    def __bytes__(self):
        return bytes(self._bitmap)


def map_key_to_row(key, count, trial):
    """
    We need to map each key to a row, so we can quickly find them.

    Taking a trial parameter so we can avoid cases where two keys map to the
    same row.

    Somewhat dumb scheme that takes a HMAC and uses the lower bits of the HMAC.

    So we can only map to the largest power of 2 below count.

    This is not great and we can improve this, but just wanted an easy solution
    for now.

    This does upper bound the number of streams that can be in a store.
    """
    max_row = 2 ** math.floor(math.log2(count))
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(struct.pack('>Q', trial))
    # module should be fine here as we are dealing with a random number that
    # will be generated uniformly in the range (0, 2**HASH_BITS).
    return int.from_bytes(h.finalize(), 'little', signed=False) % max_row
