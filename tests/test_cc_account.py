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

    assert not cc_alice.read_claim("bob_hair")

    cc_alice.add_claim(
        claim=("bob_hair", "black")
    )
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_hair")

    cc_alice.register_peer('bob', cc_bob.head_imprint, '', chain=cc_bob)
    cc_alice.add_claim(claim=("bob_feet", "4"))
    cc_alice.share_claims(["bob_feet"], reader='bob')
    cc_alice.commit_to_chain()
    assert cc_alice.read_claim("bob_feet")
    assert cc_bob.read_claim("bob_feet", chain=cc_alice)
    assert not cc_bob.read_claim("bob_hair", chain=cc_alice)