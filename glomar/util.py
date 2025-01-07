import math
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from consts import AUTHTAG_SIZE, BLOCK_SIZE


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


# https://stackoverflow.com/questions/312443/how-do-i-split-a-list-into-equally-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def pad(data, size, byte_val=b'\x00'):
    """
    Just padding the data up to a certain size
    """
    if len(data) == 0:
        return size * byte_val
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


def append_authtag(data, authtag=None):
    """
    Append an authtag back so the block can be decrypted.
    """
    # already included in data
    if authtag is None:
        return data
    assert len(authtag) == AUTHTAG_SIZE
    return data + authtag


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
