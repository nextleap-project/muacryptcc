from muacryptcc.plugin import CCAccount, export_params


def test_identity_creation(tmpdir):
    store = {}
    cc1 = CCAccount(str(tmpdir), store)
    cc2 = CCAccount(str(tmpdir), store)
    assert export_params(cc1.params) == export_params(cc2.params)
    assert cc1.params.vrf.sk
    assert cc1.params.vrf.sk == cc1.params.vrf.sk


def test_add_claim_with_access_control(tmpdir):
    store = {}
    cc_alice = CCAccount(str(tmpdir.join("alice")), store)
    cc_bob = CCAccount(str(tmpdir.join("bob")), store)
    alice_pk = cc_alice.get_public_key()
    bob_pk = cc_bob.get_public_key()

    assert not cc_alice.has_readable_claim("bob_hair")

    state = cc_alice.get_current_state()
    cc_alice.add_claim(
        state,
        claim=("bob_hair", "black"),
        access_pk=alice_pk
    )
    cc_alice.commit_state_to_chain(state)
    assert cc_alice.has_readable_claim("bob_hair")

    cc_alice.add_claim(state, claim=("bob_feet", "4"), access_pk=bob_pk)
    cc_alice.commit_state_to_chain(state)
    assert cc_alice.has_readable_claim_for(cc_bob, "bob_feet")
    assert not cc_alice.has_readable_claim_for(cc_bob, "bob_hair")
