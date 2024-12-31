"""
An implementation of a deniable storage system.

The storage system lets you access block devices by providing a key to access
them.

Need to think of something to use the spare space in the row objects.
32 bytes + 4 * 31. maybe construct a tree to store partition bitmaps.
"""
import math
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from consts import \
    BLOCK_SIZE, AUTHTAG_SIZE, KEYSIZE, BLOCKS_PER_ROW, \
    ROW_SIZE, BLOCK_ROW_DATA


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


def pad(data, size, byte_val=b'\x00'):
    """
    Just padding the data up to a certain size
    """
    to_add = size - (len(data) % size)
    if to_add == 0 or to_add == size:
        return data
    return data + to_add * byte_val


def split_authtag(data, size=AUTHTAG_SIZE):
    """
    The authentication tag is 16 bytes appended to the data, which we need to
    seperate out.
    """
    return data[:-size], data[-size:]


def append_authtag(data, authtag):
    """
    Append an authtag back so the block can be decrypted.
    """
    assert len(authtag) == AUTHTAG_SIZE
    return data + authtag


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


class GlomarBlockKey:
    """
    Key for block data.
    """

    def __init__(self, key):
        self._key = key

    def get(self, block_idx, size=KEYSIZE):
        """
        A key for a block.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=size,
            info=b'BLCK_KEY' + block_idx.to_bytes(8, byteorder='big'),
            salt=None,
        )
        return hkdf.derive(self._key)


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


def encrypt(key, nonce, data):
    chacha = ChaCha20Poly1305(key)
    return split_authtag(chacha.encrypt(nonce, data, None))


def decrypt(key, nonce, authtag, data):
    chacha = ChaCha20Poly1305(key)
    try:
        res = chacha.decrypt(nonce, append_authtag(data, authtag), None)
        return res
    except InvalidTag:
        return None


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
        self._metadata = index_block[BLOCK_ROW_DATA * (BLOCKS_PER_ROW - 1):]

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

    def set_metadata(self, metadata):
        assert len(metadata) == BLOCK_SIZE - (BLOCKS_PER_ROW - 1)
        self._metadata = metadata

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


class GlomarStoreOld:
    """
    Represents a store, which before packing exists just as a list of tuples of
    (key, data).
    """

    def __init__(self, size):
        self._size = size
        self._blobs = []
        assert size % BLOCKS_PER_ROW == 0
        # determine all the free blocks, removing the first block in each row
        # as that is used for metadata.
        self._free_blocks = \
            list(filter(lambda x: x % BLOCKS_PER_ROW != 0, range(size)))

    def allocate(self, size):
        """
        Allocate free blocks.
        """
        self._free_blocks = shuffle(self._free_blocks)
        allocated, self._free_blocks = \
            self._free_blocks[:size], self._free_blocks[size:]
        return sorted(allocated)

    def add(self, key, data):
        """
        Add a new stream.
        """
        self._blobs.append((key, len(data), data))

    def __bytes__(self):
        """
        Pack the store down to bytes.
        """
        row_count = math.ceil(self._size / BLOCKS_PER_ROW)
        rows = [GlomarRow(i * BLOCKS_PER_ROW) for i in range(row_count)]
        # add the meta data keys first so they can find them easier.
        # we need sequential ids if the bitmap we are storing exceeds 512 * 8
        # bits.

        # Allocate blocks for each stream and store them in the desired row.
        for key, length, blob in self._blobs:
            allocated = self.allocate(block_count(length))
            for idx, block in enumerate(allocated):
                row_idx = map_idx_row(block)
                curr_block = get_block(blob, idx)
                rows[row_idx].set_and_encrypt(block, key, curr_block)

        return b''.join(map(bytes, rows))


def allocate_blocks(blocks, size):
    all_blocks = shuffle(blocks)
    allocated, left = all_blocks[:size], all_blocks[size:]
    return sorted(allocated), left


class GlomarStream:
    """
    Wrapper around a stream.
    """

    def __init__(self, store, key):
        self._store = store
        self._key = key
        self._offsets = []
        self._find_offsets()

    def size(self):
        return len(self._offsets)

    def _translate_offset(self, offset):
        if offset > len(self._offsets):
            raise Exception('Out of bounds!')
        return self._offsets[offset]

    def _find_offsets(self):
        """
        Iterate through each block in the store and see which ones we can
        decrypt.
        """
        # find all the offsets by iterating through each block and seeing if
        # the key can decrypt it.
        for offset in self._store.possible():
            res = self._store.get_block(offset, self._key)
            if res is None:
                continue
            self._offsets.append(offset)

    def read(self, idx):
        """
        Read the block at idx.
        """
        block = self._store.get_block(self._translate_offset(idx), self._key)
        return bytes(block)

    def write(self, idx, data):
        """
        Write a block at idx.
        """
        self._store.set_block(self._translate_offset(idx), self._key, data)


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
    print(start, _end)
    return b''.join(stream.read(i) for i in range(start, _end))


class GlomarStore:
    """
    A Glomar Store.
    """

    def __init__(self, blob):
        self._blob = blob
        self._size = int(len(blob) / BLOCK_SIZE)
        self._row_count = math.ceil(self._size / BLOCKS_PER_ROW)
        self._rows = []
        self._modified_rows = set()
        for i in range(self._row_count):
            row_data = get_block(self._blob, i, ROW_SIZE)
            row = GlomarRow(i * BLOCKS_PER_ROW, data=row_data)
            self._rows.append(row)

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

    def partition(self, streams):
        free_blocks = list(self.possible())
        for key, length in streams:
            allocated, free_blocks = allocate_blocks(
                free_blocks, block_count(length)
            )
            if len(allocated) != block_count(length):
                raise Exception('Not enough space!')
            for idx in allocated:
                self.set_block(
                    idx,
                    key.block_key(),
                    secrets.token_bytes(BLOCK_SIZE)
                )

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

    def __bytes__(self):
        return b''.join(map(bytes, self._rows))
