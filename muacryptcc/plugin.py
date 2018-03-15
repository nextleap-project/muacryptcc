import os
import json
import pluggy
from attr import asdict
from hippiehug import Chain
from claimchain import State
from claimchain.crypto.params import LocalParams, Keypair
from claimchain.utils import pet2ascii
from .filestore import FileStore

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
        self.init_crypto_identity()

    def init_crypto_identity(self):
        identity_file = os.path.join(self.accountdir, 'identity.json')
        if not os.path.exists(identity_file):
            self.params = LocalParams.generate()
            state = State()
            state.identity_info = "Hi, I'm " + pet2ascii(self.params.vrf.pk)
            assert self.head is None
            self.commit_state_to_chain(state)
            assert self.head
            with open(identity_file, 'w') as fp:
                json.dump(export_params(self.params), fp)
        else:
            with open(identity_file, 'r') as fp:
                params_raw = json.load(fp)
                self.params = LocalParams.from_dict(params_raw)

    def head():
        def fget(self):
            try:
                with open(os.path.join(self.accountdir, 'head'), 'rb') as fp:
                    return fp.read()
            except IOError:
                return None

        def fset(self, val):
            with open(os.path.join(self.accountdir, 'head'), 'wb') as fp:
                fp.write(val)
        return property(fget, fset)
    head = head()

    def commit_state_to_chain(self, state):
        chain = Chain(self.store, root_hash=self.head)
        with self.params.as_default():
            self.head = state.commit(chain)

    @hookimpl
    def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
        pass


def export_params(params):
    result = {}
    for name, attr in asdict(params, recurse=False).items():
        if isinstance(attr, Keypair):
            result[name + '_pk'] = pet2ascii(attr.pk)
            result[name + '_sk'] = pet2ascii(attr.sk)
    return result

