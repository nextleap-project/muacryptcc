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


def test_add_claim_with_access_control(make_account):
    cc_alice = make_account("alice")
    cc_bob = make_account("bob")
    alice_pk = cc_alice.get_public_key()
    bob_pk = cc_bob.get_public_key()

    assert not cc_alice.has_readable_claim(b"bob_hair")

    cc_alice.add_claim(
        claim=(b"bob_hair", b"black"),
        access_pk=alice_pk
    )
    cc_alice.commit_to_chain()
    assert cc_alice.has_readable_claim(b"bob_hair")

    cc_alice.add_claim(claim=(b"bob_feet", b"4"), access_pk=bob_pk)
    cc_alice.commit_to_chain()
    assert cc_alice.has_readable_claim_for(cc_bob, b"bob_feet")
    assert not cc_alice.has_readable_claim_for(cc_bob, b"bob_hair")
