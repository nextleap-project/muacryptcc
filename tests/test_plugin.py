from muacryptcc.plugin import CCAccount, export_params


def test_identity_creation(tmpdir):
    cc1 = CCAccount(str(tmpdir))
    cc2 = CCAccount(str(tmpdir))
    assert export_params(cc1.params) == export_params(cc2.params)
    assert cc1.params.vrf.sk
    assert cc1.params.vrf.sk == cc1.params.vrf.sk


def test_add_claim_with_access_control(tmpdir):
    cc_alice = CCAccount(str(tmpdir.join("alice")))
    cc_bob = CCAccount(str(tmpdir.join("bob")))

    assert not cc_alice.has_readable_claim("bob_hair")

    state = cc_alice.get_current_state()
    cc_alice.add_claim(
        state,
        claim=("bob_hair", "black"),
        access_pk=cc_bob.get_public_key()
    )
    cc_alice.commit_state_to_chain(state)
    assert cc_alice.has_readable_claim("bob_hair")

    assert 0
    add_claim(state, alice_params, claim=("bob_feet", "4"), access_pk=bob_pk)
    alice_head = commit_state_to_chain(store, alice_params, state, head=alice_head)
    assert has_readable_claim(store, bob_params, head=alice_head, claimkey="bob_feet")
    assert not has_readable_claim(store, carol_params, head=alice_head, claimkey="bob_feet")

    print ("Bob reads encrypted claim hair: {!r}".format(
           read_claim(store, bob_params, head=alice_head, claimkey="bob_hair")))
    print ("Bob reads encrypted claim feet: {!r}".format(
           read_claim(store, bob_params, head=alice_head, claimkey="bob_feet")))
