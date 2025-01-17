# glomar2

This is an rewrite of my old project [glomar](https://github.com/bahorn/glomar),
using some better internals and working as a [nbdkit](https://gitlab.com/nbdkit/nbdkit) plugin.

This is an implementation of a [deniable encryption scheme](https://en.wikipedia.org/wiki/Deniable_encryption),
where you can create several "partitions"/streams and it shouldn't be possible
for anyone without the keys to tell what exists in the base image.

Still vulnerable to attacks where you image the drive at different points in
time and compare which blocks changed.
You should treat these as a write-once, read-many sort of thing.

As always, I wrote this for fun so don't use it for anything serious.
This is insanely slow as it essentially does random access to read each 4096 
byte block, and doesn't have any concept of extents.

## Usage

Setup:
```
# for ubuntu, your distro may vary
sudo apt install nbdkit nbdkit-plugin-python nbd-client
# generic
virtualenv -p python3 .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$PYTHONPATH:`pwd`/glomar
```

Now create a image with several partitions:
```
python3 glomar create 1024 out.bin 0102,128 0102030405060708,512
```

* 1024 is the size of the image, in multiples of the block size (512).
* out.bin is output image name.
* `0102,128` is a key (bytes encoded as hex) and the number blocks to use for
  that partitions.
* `0102030405060708,512` is the same, just with a larger key.

If you want to store a real file system you'll need to increase those.

Now you can run the server with:
```
nbdkit -v -f --log stderr python glomar/nbdkit.py disk=./out.bin
```

And mount it on your system with:
```
sudo nbd-client -N 0102030405060708 localhost
```
The export name is the key encoded as hex to use.

This will output the name of the device in `/dev/` it is mounted under, which is
probably `/dev/nbd0` and as root you can read / write it to change the contents
of the partition.

Finally when done, delete the block device with nbd-client:
```
sudo nbd-client -d /dev/nbd0
```

## Internals

The core structure is what I'm calling a row, which is a bundle of blocks that
can be used to store data and one header block.
This is done so all the data blocks can have the same underlaying blocksize
(512 bytes) and not have to keep the metadata inline in the block.
The metadata is moved to the header block, which stores the nonce +
authentication tag for each block (and maybe other metadata I need to store
later on?)

A single volume can have many rows concatenated to each other, you just index
blocks by row.

When you access a volume and give a key, you get a stream / partition which is
created by looking at all the blocks and seeing which ones we can decrypt with
that key.
To make lookup less slow, you first look at the row headers to find a bitmap
describing which blocks are used for the stream.

The blocks used for each stream is random and decided at partition time, which
only occurs once when you create the volume. While it is possible technically to
create new partitions after the fact if you know all the keys, the code does not
support this.


## License

MIT
