"""
An implementation of a deniable storage system.

The storage system lets you access block devices by providing a key to access
them.
"""
import math
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from consts import \
    BLOCK_SIZE, KEYSIZE, BLOCKS_PER_ROW, \
    ROW_SIZE, BLOCK_ROW_DATA, ROW_METADATA_OFFSET, ROW_METADATA_SIZE, \
    USABLE_METADATA_SIZE, NONCE_SIZE, MAX_TRIALS
from util import encrypt, decrypt, pad
from streammap import Bitmap, map_key_to_row, store_tree, get_leaves, TreeNode


def block_count(data_len, size=BLOCK_SIZE):
    """
    Map the length to a number of blocks.
    """
    return math.ceil(data_len / size)


def get_block(data, idx, size=BLOCK_SIZE):
    """
    Return the block at idx from data
    """
    return data[idx * size:(idx + 1) * size]


def pack_nonce_and_authtag(nonce, authtag):
    """
    pack the nonce and authtag into BLOCK_ROW_DATA bytes
    """
    assert len(nonce) == 12
    assert len(authtag) == 16
    return nonce + authtag


def unpack_nonce_and_authtag(data):
    """
    Extract the nonce and authtag from data
    """
    nonce = data[:12]
    authtag = data[12:12 + 16]
    assert len(nonce) == 12
    assert len(authtag) == 16
    return nonce, authtag


def shuffle(lst):
    """
    A fisher-yates shuffle, which is suitable for our usecase.
    """
    res = lst.copy()
    n = len(res)
    for i in range(0, n - 1):
        j = i + secrets.randbelow(n - i)
        res[j], res[i] = res[i], res[j]
    return res


class GlomarKey:
    """
    Key for block data.
    """
    INFO = None

    def __init__(self, key):
        self._key = key
        assert self.INFO is not None

    def get(self, block_idx=0, size=KEYSIZE):
        """
        A key for a block.
        """
        info = self.INFO
        info += block_idx.to_bytes(8, byteorder='big')

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=size,
            info=info,
            salt=None,
        )
        return hkdf.derive(self._key)


class GlomarBlockKey(GlomarKey):
    """
    Generic block key.
    """
    INFO = b'BLOCK_KEY'


class GlomarBitmapKey(GlomarKey):
    """
    This key is used to store encrypt the bitmap.
    """
    INFO = b'BITMAP_KEY'


class GlomarMapKey(GlomarKey):
    """
    This key is used to map the tree to a row index and is not directly used
    for encryption.
    """
    INFO = b'MAP_KEY'


class GlomarRootKey(GlomarKey):
    """
    The root of the tree is encrypted using this key.
    """
    INFO = b'ROOT_KEY'


class GlomarTreeKey(GlomarKey):
    """
    Each non-root node of the tree is encrypted using this key.
    """
    INFO = b'TREE_KEY'


class GlomarBaseKey:
    """
    A base key, which you call methods on to obtain keys that are to be used in
    different scopes.
    """

    def __init__(self, key):
        prekey = key if isinstance(key, bytes) else bytes(key, 'utf-8')
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            info=b'PRE_KEYZ',
            salt=None
        )
        self._key = hkdf.derive(prekey)

    def block_key(self):
        return GlomarBlockKey(self._key)

    def bitmap_key(self):
        return GlomarBitmapKey(self._key)

    def map_key(self):
        return GlomarMapKey(self._key)

    def root_key(self):
        return GlomarRootKey(self._key)

    def tree_key(self):
        return GlomarTreeKey(self._key)


class GlomarBlock:
    def __init__(self, idx, data=None):
        self._idx = idx
        if data is None:
            self._data = secrets.token_bytes(BLOCK_SIZE)
        else:
            assert len(data) == BLOCK_SIZE
            self._data = data

    def index(self):
        return self._idx

    def set_data(self, data):
        """
        Set the data in the block
        """
        assert len(data) == BLOCK_SIZE
        self._data = data

    def __bytes__(self):
        return self._data


class GlomarRow:
    """
    To construct the packed representation of the Glomar store.
    We use rows of BLOCKS_PER_ROW blocks, with BLOCKS_PER_ROW - 1 being normal
    storage blocks and the one remaining one stores the authentication codes.

    This has a bit of spare space, so need to figure out what to do with that.
    * The spare bytes in the (nonce, authkey) bytes to reach 32 bytes.
    * the 32 byte slot at index 0 in the header.
    """

    def __init__(self, offset, data=None, row=BLOCKS_PER_ROW):
        self._row = row
        self._offset = offset
        curr_data = data
        if curr_data is None:
            curr_data = secrets.token_bytes(BLOCKS_PER_ROW * BLOCK_SIZE)

        self._extract(curr_data)

    def _extract(self, data):
        """
        Extract the information from the data
        """
        assert len(data) == BLOCKS_PER_ROW * BLOCK_SIZE

        self._blocks = []
        self._nonces = []
        self._authtags = []
        index_block = get_block(data, 0)

        for i in range(1, self._row):
            block = GlomarBlock(self._offset + i, get_block(data, i))
            self._blocks.append(block)
            nonce, authtag = unpack_nonce_and_authtag(
                get_block(index_block, i - 1, BLOCK_ROW_DATA)
            )
            self._nonces.append(nonce)
            self._authtags.append(authtag)
        self._metadata = index_block[ROW_METADATA_OFFSET:]

    def set_and_encrypt(self, idx, key, data):
        """
        Set the block at idx to data encrypted with key
        """
        for block_idx, block in enumerate(self._blocks):
            if block.index() != idx:
                continue

            nonce = secrets.token_bytes(12)
            data, auth_tag = encrypt(key.get(idx), nonce, data)
            block.set_data(data)
            self._nonces[block_idx] = nonce
            self._authtags[block_idx] = auth_tag
            return
        raise Exception(f'Could not find block index {idx}')

    def get_and_decrypt(self, idx, key):
        for block_idx, block in enumerate(self._blocks):
            if block.index() != idx:
                continue
            return decrypt(
                key.get(idx),
                self._nonces[block_idx],
                self._authtags[block_idx],
                bytes(block)
            )
        raise Exception(f'Could not find block index {idx}')

    def get_metadata(self):
        return self._metadata

    def get_and_decrypt_metadata(self, key):
        metadata = self.get_metadata()
        nonce, data = metadata[:NONCE_SIZE], metadata[NONCE_SIZE:]
        return decrypt(key.get(self._offset), nonce, None, data)

    def set_metadata(self, metadata):
        assert len(metadata) == ROW_METADATA_SIZE
        self._metadata = metadata

    def set_and_encrypt_metadata(self, key, metadata):
        assert len(metadata) == USABLE_METADATA_SIZE
        nonce = secrets.token_bytes(12)
        encrypted_metadata, auth_tag = encrypt(
            key.get(self._offset),
            nonce,
            metadata
        )
        packed = nonce + encrypted_metadata + auth_tag
        self.set_metadata(packed)

    def gen_header(self):
        """
        Generate a header block.
        """
        all = []
        for nonce, authtag in zip(self._nonces, self._authtags):
            if nonce is None or authtag is None:
                all.append(secrets.token_bytes(BLOCK_ROW_DATA))
                continue
            packed = pack_nonce_and_authtag(nonce, authtag)
            all.append(packed)
        res = b''.join(all) + self._metadata
        assert len(res) == BLOCK_SIZE
        return res

    def __bytes__(self):
        header = self.gen_header()
        return header + b''.join(map(bytes, self._blocks))


def map_idx_row(idx):
    """
    Just translate a block index to a row.
    """
    row = math.floor(idx / BLOCKS_PER_ROW)
    return row


def allocate_blocks(blocks, size):
    all_blocks = shuffle(blocks)
    allocated, left = all_blocks[:size], all_blocks[size:]
    return sorted(allocated), left


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


# https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


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


class GlomarStore:
    """
    A Glomar Store.
    """

    def __init__(self, blob):
        self._blob = blob
        self._size = int(len(blob) / BLOCK_SIZE)
        self._row_count = math.floor(self._size / BLOCKS_PER_ROW)
        self._rows = []
        self._modified_rows = set()
        for i in range(self._row_count):
            row_data = get_block(self._blob, i, ROW_SIZE)
            row = GlomarRow(i * BLOCKS_PER_ROW, data=row_data)
            self._rows.append(row)
        self._free_rows = []

    def row_count(self):
        return self._row_count

    def modified_rows(self):
        """
        Tracking the rows that have been changed to just be a bit easier on the
        disk.
        """
        return self._modified_rows

    def reset_modified_rows(self):
        """
        Reset the rows which have been modified, to be called after a disk
        flush.
        """
        self._modified_rows = set()

    def _allocate(self, key, length, free_blocks, data=None, initialize=True):
        allocated, free_blocks = allocate_blocks(
            free_blocks, block_count(length)
        )
        if len(allocated) != block_count(length):
            raise Exception('Not enough space!')

        if data:
            write_stream(self.get_raw(key, allocated), data)

        if data is None and initialize:
            for idx in allocated:
                self.set_block(
                    idx,
                    key,
                    secrets.token_bytes(BLOCK_SIZE)
                )
        return allocated, free_blocks

    def allocate_row(self):
        allocated, self._free_rows = allocate_blocks(self._free_rows, 1)
        return allocated[0]

    def partition(self, streams, initialize=True):
        """
        partition the store.

        You can set initialize to false if you are using a bitmap to index the
        streams, otherwise you need it set to find the allocated blocks.
        """
        free_blocks = list(self.possible())
        bitmaps = []
        metadata = []
        # first we allocate the streams normally.
        for key, length in streams:
            allocated, free_blocks = self._allocate(
                key.block_key(), length, free_blocks, initialize=initialize
            )
            bitmap = Bitmap(BLOCKS_PER_ROW * self._row_count)
            bitmap.set_bits(allocated)
            bitmaps.append((key, bytes(bitmap)))

        # now we add in the bitmaps
        for key, bitmap in bitmaps:
            allocated, free_blocks = self._allocate(
                key.bitmap_key(),
                len(bitmap),
                free_blocks,
                pad(bitmap, BLOCK_SIZE)
            )
            metadata.append((key, allocated))

        seen = set([None])
        metadata_dict = {}
        # get the row where the root of the tree is stored.
        for key, blocks in metadata:
            row_idx = None
            for _ in range(MAX_TRIALS):
                # we generate i randomly to avoid an attack.
                # basically, if you do this sequentially it becomes possible to
                # infer that another stream exists if you have a stream that is
                # mapped to what would be its index 0.
                i = secrets.randbelow(MAX_TRIALS)
                row_idx_ = map_key_to_row(
                    key.map_key().get(),
                    self._row_count,
                    i
                )
                if row_idx_ not in seen:
                    seen.add(row_idx_)
                    row_idx = row_idx_
                    break
            if row_idx is None:
                raise Exception('too many collisions!')

            metadata_dict[row_idx] = (key, blocks)

        self._free_rows = list(filter(
            lambda x: x not in seen,
            [i for i in range(self._row_count)]
        ))

        for row_idx, (key, blocks) in metadata_dict.items():
            store_tree(self, key, blocks, root=row_idx)

    def size(self):
        """
        Get the size of the store.
        """
        return self._size

    def possible(self):
        """
        Return the possible blocks that can be used to storage
        """
        return filter(lambda x: x % BLOCKS_PER_ROW != 0, range(self._size))

    def get_block(self, offset, key):
        """
        Attempt to decrypt a block with the given key.
        """
        row_idx = map_idx_row(offset)
        block = self._rows[row_idx].get_and_decrypt(offset, key)
        if not block:
            return None
        return block

    def set_block(self, offset, key, data):
        """
        Write a block.
        """
        row_idx = map_idx_row(offset)
        self._modified_rows = self._modified_rows.union([row_idx])
        self._rows[row_idx].set_and_encrypt(offset, key, data)

    def get_row(self, row_idx):
        return self._rows[row_idx]

    def get_iterative(self, key):
        """
        Get the stream for the key by iterating through each block and checking
        if we can decrypt it.
        """
        return GlomarStream(self, key)

    def get_raw(self, key, offsets):
        """
        A stream with predefined offsets.
        """
        return GlomarStreamRaw(self, key, offsets)

    def get_random(self, key):
        return GlomarStreamRandomAccess(self, key)

    def __bytes__(self):
        return b''.join(map(bytes, self._rows))
