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
        click.echo("found account %r" % str(name))
        click.echo("Head Imprint: %r" % cc_account.head_imprint)
        click.echo("Remote Url: %r" % cc_account.store.url)
        click.echo("CC data stored in %r" % cc_account.accountdir)
        click.echo("%r entries." % len(cc_account.store))


@mycommand("cc-send")
@click.argument("account_name", type=str, required=True)
@click.argument("url", type=str, required=True)
@click.pass_context
def cc_send(ctx, account_name, url):
    """send blocks to remote place. """
    acc = get_cc_account(ctx, account_name)
    click.echo("found account %r" % account_name)
    for name, value in acc.store.items():
        print(name, value)
