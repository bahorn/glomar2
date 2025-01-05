from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from consts import AUTHTAG_SIZE


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
