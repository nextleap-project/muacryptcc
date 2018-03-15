import os
import base64
import msgpack
from hippiehug.Nodes import h, Leaf, Branch
from hippiehug.Chain import Block


def default(obj):
    """ Serialize objects using msgpack. """
    if isinstance(obj, Leaf):
        datab = msgpack.packb((obj.item, obj.key))
        return msgpack.ExtType(42, datab)
    if isinstance(obj, Branch):
        datab = msgpack.packb((obj.pivot, obj.left_branch, obj.right_branch))
        return msgpack.ExtType(43,  datab)
    if isinstance(obj, Block):
        datab = msgpack.packb((obj.items, obj.index, obj.fingers, obj.aux))
        return msgpack.ExtType(44,  datab)
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

    return ExtType(code, data)


class FileStore:
    def __init__(self, dir):
        self.cache = {}
        self._dir = dir
        if not os.path.exists(dir):
            os.makedirs(dir)

    def __getitem__(self, key):
        if key in self.cache:
            return self.cache[key]
        if len(self.cache) > 10000:
            self.cache = {}

        bdata = self.file_get(key)
        branch = msgpack.unpackb(bdata, ext_hook=ext_hook)
        # assert key == branch.identity()
        self.cache[key] = branch
        return branch

    def __setitem__(self, key, value):
        if key in self.cache:
            return
        bdata = msgpack.packb(value, default=default)
        # assert key == value.identity()
        self.file_set(key, bdata)

    def file_set(self, key, value):
        if not isinstance(value, bytes):
            raise ValueError("Value must be of type bytes")
        bn = base64.b64encode(key)
        with open(os.path.join(self._dir, bn), "wb") as f:
            f.write(value)
            print("store-set {}={!r}".format(bn, value))

    def file_get(self, key):
        bn = base64.b64encode(key)
        try:
            with open(os.path.join(self._dir, bn), "rb") as f:
                val = f.read()
                print("store-get {} -> {!r}".format(bn, val))
            return val
        except IOError:
            raise KeyError(key)

    def items(self):
        try:
            raw_keys = os.listdir(self._dir)
        except OSError:
            raw_keys = []
        for raw_key in raw_keys:
            key = base64.b64decode(raw_key)
            val = self[key]
            yield key, val
