from __future__ import print_function, unicode_literals

import os
import json
import pluggy
from hippiehug import Chain
from claimchain import State, View
from claimchain.crypto.params import LocalParams
from claimchain.utils import pet2ascii

hookimpl = pluggy.HookimplMarker("muacrypt")


@hookimpl
def instantiate_account(plugin_manager, basedir):
    cc_dir = os.path.join(basedir, "muacryptcc")
    cc_manager = CCAccount(cc_dir)
    plugin_manager.register(cc_manager)


class CCAccount(object):
    def __init__(self, accountdir, store=None):
        self.accountdir = accountdir
        if not os.path.exists(accountdir):
            os.makedirs(accountdir)
        self.store = store
        self.init_crypto_identity()

    #
    # muacrypt plugin hook implementations
    #
    @hookimpl
    def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
        assert dec_msg["GossipClaims"]

    @hookimpl
    def process_outgoing_before_encryption(self, account_key, msg):
        msg["GossipClaims"]=pet2ascii(self.head)

    def init_crypto_identity(self):
        identity_file = os.path.join(self.accountdir, 'identity.json')
        if not os.path.exists(identity_file):
            self.params = LocalParams.generate()
            self.state = State()
            self.state.identity_info = "Hi, I'm " + pet2ascii(self.params.vrf.pk)
            assert self.head is None
            self.commit_to_chain()
            assert self.head
            with open(identity_file, 'w') as fp:
                json.dump(self.params.private_export(), fp)
        else:
            with open(identity_file, 'r') as fp:
                params_raw = json.load(fp)
                self.params = LocalParams.from_dict(params_raw)
                # TODO: load state from last block
                self.state = State()

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

    def commit_to_chain(self):
        chain = self._get_current_chain()
        with self.params.as_default():
            self.head = self.state.commit(chain)

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

    def add_claim(self, claim, access_pk=None):
        # print("add-claim", repr(claim), repr(access_pk))
        key, value = claim
        assert isinstance(key, bytes)
        assert isinstance(value, bytes)
        self.state[key] = value
        if access_pk is not None:
            with self.params.as_default():
                self.state.grant_access(access_pk, [key])

    def _get_current_chain(self):
        return Chain(self.store, root_hash=self.head)
