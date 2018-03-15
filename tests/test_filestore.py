import pytest
from muacryptcc.filestore import FileStore

def test_file_store(tmpdir):
    store = FileStore(str(tmpdir))
    with pytest.raises(KeyError):
        store.file_get('key')
    assert not list(store.items())
    store.file_set('key', b'value')
    assert b'value' == store.file_get('key')
    with pytest.raises(ValueError):
        store.file_set('key', 32)
    store2 = FileStore(str(tmpdir))
    assert b'value' == store2.file_get('key')

