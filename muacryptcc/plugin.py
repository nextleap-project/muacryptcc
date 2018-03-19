from __future__ import print_function, unicode_literals

import os
import json
import pluggy
from attr import asdict
from hippiehug import Chain
from claimchain import State, View
from claimchain.crypto.params import LocalParams, Keypair
from claimchain.utils import pet2ascii

hookimpl = pluggy.HookimplMarker("muacrypt")


@hookimpl
def instantiate_account(plugin_manager, basedir):
    cc_dir = os.path.join(basedir, "muacryptcc")
    cc_manager = CCAccount(cc_dir)
    plugin_manager.register(cc_manager)


class CCAccount:
    def __init__(self, accountdir, store=None):
        self.accountdir = accountdir
        if not os.path.exists(accountdir):
            os.makedirs(accountdir)
        self.store = store
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

    def get_public_key(self):
        return self.params.dh.pk
        # chain = self._get_current_chain()
        # with self.params.as_default():
        #     return View(chain).params.dh.pk

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

    def _get_current_chain(self):
        return Chain(self.store, root_hash=self.head)

    def get_current_state(self):
        return State()

    def commit_state_to_chain(self, state):
        chain = self._get_current_chain()
        with self.params.as_default():
            self.head = state.commit(chain)

    def read_claim(self, claimkey):
        return self.read_claim_as(self, claimkey)

    def read_claim_as(self, other, claimkey):
        assert isinstance(claimkey, bytes)
        print("read-claim-as", other, repr(claimkey))
        chain = self._get_current_chain()
        with other.params.as_default():
            return View(chain)[claimkey]

    def has_readable_claim(self, claimkey):
        return self.has_readable_claim_for(self, claimkey)

    def has_readable_claim_for(self, other, claimkey):
        assert isinstance(claimkey, bytes)
        try:
            self.read_claim_as(other, claimkey)
        except (KeyError, ValueError):
            return False
        return True

    def add_claim(self, state, claim, access_pk=None):
        # print("add-claim", repr(claim), repr(access_pk))
        key, value = claim
        assert isinstance(key, bytes)
        assert isinstance(value, bytes)
        state[key] = value
        if access_pk is not None:
            with self.params.as_default():
                state.grant_access(access_pk, [key])

    #
    # muacrypt plugin hook implementations
    #
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
