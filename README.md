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

## License

MIT
