import os
import json
import pluggy
from attr import asdict
from claimchain.crypto.params import LocalParams, Keypair
from claimchain.utils import pet2ascii


hookimpl = pluggy.HookimplMarker("muacrypt")


@hookimpl
def instantiate_account(plugin_manager, basedir):
    cc_dir = os.path.join(basedir, "muacryptcc")
    cc_manager = CCAccount(cc_dir)
    plugin_manager.register_plugin(cc_manager)


class CCAccount:

    def __init__(self, accountdir):
        self.accountdir = accountdir
        self.store = FileStore(os.path.join(accountdir, 'filestore'))
        self.params = self.init_crypto_identity()

    def init_crypto_identity(self):
        identity_file = os.path.join(self.accountdir, 'identity.json')
        if not os.path.exists(identity_file):
            params = LocalParams.generate()
            with open(identity_file, 'w') as fp:
                json.dump(export_params(params), fp)
        else:
            with open(identity_file, 'r') as fp:
                params_raw = json.load(fp)
                params = LocalParams.from_dict(params_raw)
        return params

        # state = State()
        # state.identity_info = "Hi, I'm " + name

        # Generate cryptographic keys
        # params = LocalParams.generate()
        # return commit_state_to_chain(store, params, state, head=None), params

        # create accountdir

    @hookimpl
    def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
        pass


class FileStore():

    def __init__(self, dir):
        pass

    def __setitem__(self, key, value):
        print("store-set {}={}".format(base64.b64encode(key), value))
        super(MyStore, self).__setitem__(key, value)

    def __getitem__(self, key):
        val = super(MyStore, self).__getitem__(key)
        print("store-get {} -> {}".format(base64.b64encode(key), val))
        return val


def export_params(params):
    result = {}
    for name, attr in asdict(params, recurse=False).items():
        if isinstance(attr, Keypair):
            result[name + '_pk'] = pet2ascii(attr.pk)
            result[name + '_sk'] = pet2ascii(attr.sk)
    return result

