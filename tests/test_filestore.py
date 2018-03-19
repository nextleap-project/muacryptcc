import pytest
from muacryptcc.filestore import FileStore, key2basename, basename2key


def test_basename_encoding():
    key = b'\0\17/13'
    assert basename2key(key2basename(key)) == key


def test_file_store(tmpdir):
    store = FileStore(str(tmpdir))
    with pytest.raises(KeyError):
        store.file_get(b'key')
    assert not list(store.items())
    store.file_set(b'key', b'value')
    assert b'value' == store.file_get(b'key')
    with pytest.raises(ValueError):
        store.file_set(b'key', 32)
    store2 = FileStore(str(tmpdir))
    assert b'value' == store2.file_get(b'key')
