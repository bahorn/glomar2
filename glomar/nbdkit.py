#!/usr/bin/nbdkit python
"""
Glomar NBDKIT plugin
"""
import binascii
import builtins
import nbdkit
import math
from core import GlomarStore, GlomarBaseKey, read_stream, write_stream
from consts import BLOCK_SIZE

API_VERSION = 2

_config = {'disk': None}
store = None


def config(key, value):
    global _config
    _config[key] = value


def flush_real():
    with builtins.open(_config['disk'], 'wb') as f:
        f.write(bytes(store))


def open(readonly):
    global _config
    global store
    if _config['disk'] is None:
        raise Exception('No disk defined')

    key = binascii.unhexlify(nbdkit.export_name())
    nbdkit.debug(f'Using key: {key}')
    key = GlomarBaseKey(key)

    if store is None:
        with builtins.open(_config['disk'], 'rb') as f:
            store = GlomarStore(f.read())

    res = store.get_iterative(key.block_key())

    return res


def close(h):
    flush_real()


def get_size(h):
    nbdkit.debug(f'size: {h.size()}')
    return h.size() * BLOCK_SIZE


def block_size(h):
    return BLOCK_SIZE


def can_fua(h):
    return nbdkit.FUA_NONE


def export_description(h):
    return 'glomar'


def pread(h, buf, offset, flags):
    to_read = math.ceil(len(buf) / BLOCK_SIZE)
    start_offset = offset % BLOCK_SIZE
    if start_offset != 0:
        to_read += 1
    start_block = math.floor(offset / BLOCK_SIZE)
    end_block = start_block + to_read
    buf[:] = read_stream(h, start=start_block, end=end_block)[start_offset:]


def pwrite(h, buf, offset, flags):
    to_read = math.ceil(len(buf) / BLOCK_SIZE)
    start_offset = offset % BLOCK_SIZE
    if start_offset != 0:
        to_read += 1
    start_block = math.floor(offset / BLOCK_SIZE)
    end_block = start_block + to_read
    # first we read all the blocks we are going to overwrite
    original = bytearray(read_stream(h, start=start_block, end=end_block))
    original[start_offset:start_offset + len(buf)] = buf
    write_stream(h, bytes(original), start=start_block)


def can_flush(h):
    return True


def flush(h, flags):
    flush_real()
