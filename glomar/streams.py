from keys import GlomarBaseKey
from streammap import TreeNode, Bitmap, get_leaves, map_key_to_row
from util import chunks
from consts import BLOCK_SIZE, MAX_TRIALS


class GlomarStreamRaw:
    """
    Wrapper around a stream, with defined offsets.
    """

    def __init__(self, store, key, offsets=None):
        self._store = store
        self._key = key.block_key() if isinstance(key, GlomarBaseKey) else key
        self._offsets = self._find_offsets(store, key) \
            if offsets is None else offsets

    def _find_offsets(self, store, key):
        return []

    def size(self):
        return len(self._offsets)

    def _translate_offset(self, offset):
        if offset > len(self._offsets):
            raise Exception('Out of bounds!')
        return self._offsets[offset]

    def read(self, idx):
        """
        Read the block at idx.
        """
        block = self._store.get_block(
            self._translate_offset(idx),
            self._key
        )
        return bytes(block)

    def write(self, idx, data):
        """
        Write a block at idx.
        """
        self._store.set_block(
            self._translate_offset(idx),
            self._key,
            data
        )


class GlomarStream(GlomarStreamRaw):
    """
    Stream where the offsets are discovered iteratively.
    """

    def _find_offsets(self, store, key):
        """
        Iterate through each block in the store and see which ones we can
        decrypt.
        """
        # find all the offsets by iterating through each block and seeing if
        # the key can decrypt it.
        offsets = []
        for offset in store.possible():
            res = store.get_block(offset, key)
            if res is None:
                continue
            offsets.append(offset)
        return offsets


class GlomarStreamRandomAccess(GlomarStream):
    """
    A Glomar stream implementing random access.
    """

    def _find_offsets(self, store, key):
        """
        Dumping the bitmap out to determine which offsets are there.
        """
        map_key = key.map_key()
        root_key = key.root_key()
        tree_key = key.tree_key()
        bitmap_key = key.bitmap_key()
        for i in range(MAX_TRIALS):
            row_idx = map_key_to_row(
                map_key.get(),
                store.row_count(),
                i
            )
            possible_row = store.get_row(row_idx)
            possible = possible_row.get_and_decrypt_metadata(root_key)
            if possible is None:
                continue
            root = TreeNode(row_idx, possible)
            leaves = get_leaves(store, tree_key, root)
            raw_bitmap = read_stream(
                GlomarStreamRaw(store, bitmap_key, leaves)
            )
            return Bitmap(len(raw_bitmap) * 8, bitmap=raw_bitmap).get_offsets()

        raise Exception('Could get bitmap')


def write_stream(stream, data, start=0):
    """
    Write a stream.
    """
    for idx, chunk in enumerate(chunks(data, BLOCK_SIZE)):
        stream.write(start + idx, chunk)


def read_stream(stream, start=0, end=None):
    """
    Read a full stream.
    """
    _end = end
    if _end is None:
        _end = stream.size()
    return b''.join(stream.read(i) for i in range(start, _end))
