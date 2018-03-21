import pytest
from muacryptcc import plugin


@pytest.fixture
def my_account_maker(request, account_maker):
    def my_account_maker(*args, **kwargs):
        account = account_maker(*args, **kwargs)
        plugin.instantiate_account(
            plugin_manager=account.plugin_manager,
            basedir=account._states.dirpath,
        )
        return account
    return my_account_maker
