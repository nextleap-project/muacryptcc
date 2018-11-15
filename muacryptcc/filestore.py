import os
import requests

from base58 import b58encode, b58decode
import msgpack
from hippiehug.Nodes import Leaf, Branch
from claimchain.utils.wrappers import Blob
from hippiehug.Chain import Block


def key2basename(key):
    return b58encode(key).decode("ascii")


def basename2key(basename):
    if not isinstance(basename, bytes):
        basename = basename.encode("ascii")
    return b58decode(basename)


def value_from_data(bdata):
    branch = msgpack.unpackb(bdata, ext_hook=ext_hook)
    if isinstance(branch, bytes):
        return Blob(branch)
    # assert key == branch.identity()
    return branch


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
    def __init__(self, dir, url="http://test1:password1@localhost:5000"):
        assert dir
        # TODO: remove default and assert url
        self._dir = dir
        self.url = url
        if not os.path.exists(dir):
            os.makedirs(dir)

    def __getitem__(self, key):
        bn = key2basename(key)
        try:
            bdata = self._file_get(bn)
        except KeyError:
            self.recv(key)
            bdata = self._file_get(bn)
        return value_from_data(bdata)

    def __setitem__(self, key, value):
        bn = key2basename(key)
        bdata = msgpack.packb(value, default=default)
        # assert key == value.identity()
        self._file_set(bn, bdata)

    def __len__(self):
        try:
            keys = os.listdir(self._dir)
        except OSError:
            keys = []
        return len(keys)

    def send(self):
        for bn, data in self.files():
            r = requests.put(self.url + "/" + bn, data)
            assert r.status_code in [200, 202]

    def recv(self, key):
        bn = key2basename(key)
        r = requests.get(self.url + "/" + bn)
        if not r.status_code in [200, 202]:
            raise KeyError(key)
        data = r.content
        if not isinstance(data, bytes):
            raise ValueError("data must be of type bytes")
        with open(os.path.join(self._dir, bn), "wb") as f:
            f.write(data)

    def _file_set(self, bn, data):
        if not isinstance(data, bytes):
            raise ValueError("Value must be of type bytes")
        with open(os.path.join(self._dir, bn), "wb") as f:
            f.write(data)
            # print("store-set {!r}={!r}".format(bn, value))

    def items(self):
        for raw_key, raw_data in self.files():
            yield basename2key(raw_key), value_from_data(raw_data)

    def files(self):
        try:
            keys = os.listdir(self._dir)
        except OSError:
            keys = []
        for key in keys:
            yield key, self._file_get(key)

    def _file_get(self, bn):
        try:
            with open(os.path.join(self._dir, bn), "rb") as f:
                val = f.read()
                # print("store-get {!r} -> {!r}".format(bn, val))
            return val
        except IOError:
            raise KeyError(bn)
