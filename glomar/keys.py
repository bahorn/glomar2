"""
Our key formats.
"""
from consts import KEYSIZE
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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
