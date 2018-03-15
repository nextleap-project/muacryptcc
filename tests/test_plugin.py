from muacryptcc.plugin import CCAccount, export_params


def test_identity_creation(tmpdir):
    cc1 = CCAccount(str(tmpdir))
    cc2 = CCAccount(str(tmpdir))
    assert export_params(cc1.params) == export_params(cc2.params)
    assert cc1.params.vrf.sk
    assert cc1.params.vrf.sk == cc1.params.vrf.sk
