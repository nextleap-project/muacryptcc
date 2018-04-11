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
    assert cc1.params.vrf.sk
    assert cc1.params.vrf.sk == cc1.params.vrf.sk
    assert cc1.head
    assert cc1.head == cc2.head


def test_add_claim_with_access_control(make_account):
    cc_alice = make_account("alice")
    cc_bob = make_account("bo")
    bob_pk = cc_bob.get_public_key()

    assert not cc_alice.read_claim("bob_hair")

    cc_alice.add_claim(
        claim=("bob_hair", "black")
    )
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_hair")

    cc_alice.add_claim(claim=("bob_feet", "4"), access_pk=bob_pk)
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_feet", reader=cc_bob)
    assert cc_alice.read_claim("bob_feet", reader=cc_alice)
    assert not cc_alice.read_claim("bob_hair", reader=cc_bob)
