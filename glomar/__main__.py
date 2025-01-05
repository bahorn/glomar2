import argparse
import binascii
import secrets
from core import \
        GlomarBaseKey, GlomarRow, GlomarStore, read_stream, write_stream
from consts import ROW_SIZE, BLOCK_SIZE
from util import pad


def test_row():
    for i in range(512):
        key = GlomarBaseKey(b'\x01\x02\x03\x04\x05\x06\x07\x08')
        row = GlomarRow(i * ROW_SIZE)
        for j in range(1, 5):
            row.set_and_encrypt(
                i * ROW_SIZE + j, key.block_key(), b'\x01'*BLOCK_SIZE
            )
            a = bytes(row)
            b = GlomarRow(i * ROW_SIZE, data=a)
            assert b.get_and_decrypt(i * ROW_SIZE + j, key.block_key())


def test():
    test_row()
    key = GlomarBaseKey(b'\x01\x02\x03\x04\x05\x06\x07\x08')
    data = pad(open('/etc/passwd', 'rb').read(), BLOCK_SIZE)
    gs = GlomarStore(secrets.token_bytes(BLOCK_SIZE * 1024))
    gs.partition([(key, len(data))])
    s = gs.get_iterative(key.block_key())
    write_stream(s, data)
    print(read_stream(s))
    d = bytes(gs)
    gsb = GlomarStore(d)
    it = gsb.get_iterative(key.block_key())
    assert it.size() > 0
    print(read_stream(s))


def extract_partitions(parts):
    res = []
    for part in parts:
        key, size = part.split(',', 1)
        size = int(size) * BLOCK_SIZE
        key = GlomarBaseKey(binascii.unhexlify(key))
        res.append((key, size))

    return res


def main():
    parser = argparse.ArgumentParser(prog='glomar')
    subparsers = parser.add_subparsers(dest="command")
    create = subparsers.add_parser('create')
    create.add_argument('size', type=int)
    create.add_argument('filename')
    create.add_argument('partitions', nargs='+')

    subparsers.add_parser('test')
    args = parser.parse_args()

    match args.command:
        case 'create':
            gs = GlomarStore(secrets.token_bytes(BLOCK_SIZE * args.size))
            partitions = extract_partitions(args.partitions)
            gs.partition(partitions)
            with open(args.filename, 'wb') as f:
                f.write(bytes(gs))

        case 'test':
            test()


if __name__ == "__main__":
    main()
