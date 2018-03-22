import os

from base58 import b58encode, b58decode
import msgpack
from hippiehug.Nodes import Leaf, Branch
from claimchain.utils.wrappers import Blob
from hippiehug.Chain import Block


def key2basename(key):
    return b58encode(key)


def basename2key(basename):
    return b58decode(basename)


def default(obj):
    """ Serialize objects using msgpack. """
    if isinstance(obj, Leaf):
        datab = msgpack.packb((obj.item, obj.key))
        return msgpack.ExtType(42, datab)
    if isinstance(obj, Branch):
        datab = msgpack.packb((obj.pivot, obj.left_branch, obj.right_branch))
        return msgpack.ExtType(43, datab)
    if isinstance(obj, Block):
        datab = msgpack.packb((obj.items, obj.index, obj.fingers, obj.aux))
        return msgpack.ExtType(44, datab)
    raise TypeError("Unknown Type: %r" % (obj,))


def ext_hook(code, data):
    """ Deserialize objects using msgpack. """
    if code == 42:
        l_item, l_key = msgpack.unpackb(data)
        return Leaf(l_item, l_key)
    if code == 43:
        piv, r_leaf, l_leaf = msgpack.unpackb(data)
        return Branch(piv, r_leaf, l_leaf)
    if code == 44:
        items, index, fingers, aux = msgpack.unpackb(data)
        return Block(items, index, fingers, aux)
    return msgpack.ExtType(code, data)


class FileStore:
    def __init__(self, dir):
        assert dir
        self._dir = dir
        if not os.path.exists(dir):
            os.makedirs(dir)

    def __getitem__(self, key):
        bdata = self.file_get(key)
        branch = msgpack.unpackb(bdata, ext_hook=ext_hook)
        if isinstance(branch, bytes):
            return Blob(branch)
        # assert key == branch.identity()
        return branch

    def __setitem__(self, key, value):
        bdata = msgpack.packb(value, default=default)
        # assert key == value.identity()
        self.file_set(key, bdata)

    def file_set(self, key, value):
        if not isinstance(value, bytes):
            raise ValueError("Value must be of type bytes")
        bn = key2basename(key)
        with open(os.path.join(self._dir, bn), "wb") as f:
            f.write(value)
            # print("store-set {!r}={!r}".format(bn, value))

    def file_get(self, key):
        bn = key2basename(key)
        try:
            with open(os.path.join(self._dir, bn), "rb") as f:
                val = f.read()
                # print("store-get {!r} -> {!r}".format(bn, val))
            return val
        except IOError:
            raise KeyError(key)

    def items(self):
        try:
            encoded_keys = os.listdir(self._dir)
        except OSError:
            encoded_keys = []
        for raw_key in encoded_keys:
            key = basename2key(raw_key)
            yield key, self[key]
