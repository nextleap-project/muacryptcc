import pytest
from os import urandom
from muacryptcc.filestore import FileStore, key2basename, basename2key


def test_basename_encoding():
    key = b'\0\17/13'
    assert basename2key(key2basename(key)) == key


def test_plain_file_store(tmpdir):
    key = urandom(32)
    store = FileStore(str(tmpdir))
    with pytest.raises(KeyError):
        store[key]
    assert not list(store.items())
    store[key] = b'value'
    assert b'value' == store[key]
    store2 = FileStore(str(tmpdir))
    assert b'value' == store2[key]


def test_file_store_sync(tmpdir):
    key = urandom(32)
    source = FileStore(str(tmpdir) + '-source', "http://test1:password1@localhost:5000")
    target = FileStore(str(tmpdir) + '-target', "http://localhost:5000")
    source[key] = b'value'
    with pytest.raises(KeyError):
        target[key]
    source.send()
    assert b'value' == target[key]
