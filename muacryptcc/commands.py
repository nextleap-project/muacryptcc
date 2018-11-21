from muacrypt.cmdline_utils import mycommand, click
from muacrypt.cmdline import account_option


def get_cc_account(ctx, name):
    assert name
    # make sure the account gets instantiated so that
    # we get an already registered "ccaccount" object
    ctx.parent.account_manager.get_account(name)
    plugin_name = "ccaccount-" + name
    cc_account = ctx.parent.plugin_manager.get_plugin(name=plugin_name)
    return cc_account


@mycommand("cc-status")
@account_option
@click.pass_context
def cc_status(ctx, account_name):
    """print claimchain status for an account. """
    if account_name is None:
        names = ctx.parent.account_manager.list_account_names()
    else:
        names = [account_name]

    for name in names:
        cc_account = get_cc_account(ctx, name)
        assert cc_account
        click.echo("found account %r" % str(name))
        click.echo("Head Imprint: %r" % cc_account.head_imprint)
        click.echo("Remote Url: %r" % cc_account.store.url)
        click.echo("CC data stored in %r" % cc_account.accountdir)
        click.echo("%r entries." % len(cc_account.store))


@mycommand("cc-send")
@account_option
@click.pass_context
def cc_send(ctx, account_name):
    """send blocks to remote place. """
    acc = get_cc_account(ctx, account_name)
    click.echo("found account %r" % account_name)
    acc.upload()
