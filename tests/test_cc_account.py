from __future__ import print_function

import os
import pytest
from muacryptcc.plugin import CCAccount
from muacryptcc.filestore import FileStore


@pytest.fixture(params=["dict", "filestore"])
def make_account(request, tmpdir):
    def maker(name, store=None):
        accountdir = tmpdir.join(name).strpath
        if store is None:
            if request.param == "dict":
                store = {}
            else:
                # a global filestore where blocks from all accounts are stored
                storedir = os.path.join(str(tmpdir), "filestore")
                store = FileStore(storedir)
        return CCAccount(accountdir=accountdir, store=store)
    return maker


def test_account_can_be_propertly_instanted_from_store(make_account):
    cc1 = make_account("alice")
    cc2 = make_account("alice", store=cc1.store)

    assert cc1.params.private_export() == cc2.params.private_export()
    assert cc1.head_imprint
    assert cc1.head_imprint == cc2.head_imprint


def test_account_will_persist_peer_registry(make_account):
    alice = make_account('alice')
    bob = make_account('bob')
    alice.register_peer('bob', bob.head_imprint, 'url', bob.chain)
    from_disk = make_account("alice", store=alice.store)
    assert alice.read_claim('bob')
    assert from_disk.read_claim('bob')
    assert from_disk.read_claim('bob') == alice.read_claim('bob')


def test_add_claim_with_access_control(make_account):
    cc_alice = make_account("alice")
    cc_bob = make_account("bo")

    assert not cc_alice.read_claim("bob_hair")

    cc_alice.add_claim(
        claim=("bob_hair", "black")
    )
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_hair")

    cc_alice.register_peer('bob', cc_bob.head_imprint, '', chain=cc_bob.chain)
    cc_alice.add_claim(claim=("bob_feet", "4"))
    cc_alice.share_claims(["bob_feet"], reader='bob')
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_feet")
    assert cc_bob.read_claim("bob_feet", chain=cc_alice.chain)
    assert not cc_bob.read_claim("bob_hair", chain=cc_alice.chain)
