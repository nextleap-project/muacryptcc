import pytest


@pytest.fixture
def acmd(mycmd):
    adr = "a@autocrypt.org"
    mycmd.run_ok(["add-account", "default", "--email-regex={}".format(adr)])
    mycmd.bot_adr = adr
    return mycmd


def test_ccstatus(acmd):
    acmd.run_ok(["cc-status"])
    acmd.run_ok(["cc-status", "default"])


def test_ccsync(acmd):
    acmd.run_ok(["cc-sync", "default"])
