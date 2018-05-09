from muacrypt.cmdline_utils import mycommand, click


def get_cc_account(ctx, name):
    assert name
    # make sure the account gets instantiated so that
    # we get an already registered "ccaccount" object
    ctx.parent.account_manager.get_account(name)
    plugin_name = "ccaccount-" + name
    cc_account = ctx.parent.plugin_manager.get_plugin(name=plugin_name)
    return cc_account


@mycommand("cc-status")
@click.argument("account_name", type=str, required=False, default=None)
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
        click.echo("found account %r, XXX add info" % name)


@mycommand("cc-sync")
@click.argument("account_name", type=str, required=True)
@click.pass_context
def cc_sync(ctx, account_name):
    """synchronize blockstore for an account. """
    get_cc_account(ctx, account_name)
    click.echo("found account %r, XXX perform sync" % account_name)
