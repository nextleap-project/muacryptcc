from __future__ import print_function, unicode_literals

import logging
import os
import json
import pluggy
from hippiehug import Chain
from claimchain import State, View
from claimchain.crypto.params import LocalParams
from claimchain.utils import pet2ascii, bytes2ascii, ascii2bytes
from muacrypt.mime import parse_email_addr, get_target_emailadr
from .filestore import FileStore

hookimpl = pluggy.HookimplMarker("muacrypt")


@hookimpl
def instantiate_account(plugin_manager, basedir):
    cc_dir = os.path.join(basedir, "muacryptcc")
    store_dir = os.path.join(cc_dir, "store")
    store = FileStore(store_dir)
    cc_account = CCAccount(cc_dir, store)
    plugin_manager.register(cc_account)


class CCAccount(object):
    def __init__(self, accountdir, store=None):
        self.accountdir = accountdir
        if not os.path.exists(accountdir):
            os.makedirs(accountdir)
        self.addr2root_hash = {}
        self.addr2pk = {}
        self.store = store
        self.init_crypto_identity()

    #
    # muacrypt plugin hook implementations
    #
    @hookimpl
    def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
        root_hash = dec_msg["GossipClaims"]
        store = FileStore(dec_msg["ChainStore"])
        peers_chain = Chain(store, root_hash=ascii2bytes(root_hash))
        assert peers_chain
        view = View(peers_chain)
        peers_pk = view.params.dh.pk
        assert peers_pk
        sender = parse_email_addr(dec_msg["From"])
        self.addr2root_hash[sender] = root_hash
        self.addr2pk[sender] = peers_pk
        recipients = get_target_emailadr(dec_msg)
        for recipient in recipients:
            pagh = addr2pagh[recipient]
            value = self.read_claim(recipient, chain=peers_chain)
            if value:
                # for now we can only read claims about ourselves...
                # so if we get a value it must be our head imprint.
                assert value == bytes2ascii(pagh.keydata)

    @hookimpl
    def process_before_encryption(self, sender_addr, sender_keyhandle,
                                  recipient2keydata, payload_msg, _account):
        recipients = recipient2keydata.keys()
        if not recipients:
            logging.error("no recipients found.\n")

        for recipient in recipients:
            claim = recipient, bytes2ascii(recipient2keydata.get(recipient))
            for reader in recipients:
                pk = self.addr2pk.get(reader)
                self.add_claim(claim, access_pk=pk)

        self.commit_to_chain()
        payload_msg["GossipClaims"] = self.head_imprint
        # TODO: what do we do with dict stores?
        payload_msg["ChainStore"] = self.store._dir

    def init_crypto_identity(self):
        identity_file = os.path.join(self.accountdir, 'identity.json')
        if not os.path.exists(identity_file):
            self.params = LocalParams.generate()
            self.state = State()
            self.state.identity_info = "Hi, I'm " + pet2ascii(self.params.dh.pk)
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

    @property
    def head_imprint(self):
        return bytes2ascii(self.head)

    def commit_to_chain(self):
        chain = self._get_current_chain()
        with self.params.as_default():
            self.head = self.state.commit(chain)

    def read_claim(self, claimkey, chain=None, reader=None):
        if chain is None:
            chain = self._get_current_chain()
        if reader is None:
            reader = self
        try:
            with reader.params.as_default():
                return View(chain)[claimkey.encode('utf-8')].decode('utf-8')
        except (KeyError, ValueError):
            return None

    def add_claim(self, claim, access_pk=None):
        key, value = claim[0].encode('utf-8'), claim[1].encode('utf-8')
        assert isinstance(key, bytes)
        assert isinstance(value, bytes)
        self.state[key] = value
        with self.params.as_default():
            self.state.grant_access(self.get_public_key(), [key])
            if access_pk is not None:
                self.state.grant_access(access_pk, [key])

    def _get_current_chain(self):
        return Chain(self.store, root_hash=self.head)
