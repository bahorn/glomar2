"""
An implementation of a deniable storage system.

The storage system lets you access block devices by providing a key to access
them.
"""
import math
import secrets
from consts import \
    BLOCK_SIZE, BLOCKS_PER_ROW, \
    ROW_SIZE, BLOCK_ROW_DATA, ROW_METADATA_OFFSET, ROW_METADATA_SIZE, \
    USABLE_METADATA_SIZE, NONCE_SIZE, MAX_TRIALS
from util import encrypt, decrypt, pad, get_block, block_count, shuffle, \
        unpack_nonce_and_authtag, pack_nonce_and_authtag
from streammap import Bitmap, map_key_to_row, store_tree
from streams import write_stream, GlomarStream, GlomarStreamRandomAccess, \
    GlomarStreamRaw


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
        try:
            return self._rows[row_idx]
        except IndexError:
            raise Exception(f'{row_idx} {self._row_count}')

    def get_row_real(self, idx):
        """
        map the real idx to a row.
        """
        return idx // BLOCKS_PER_ROW

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
