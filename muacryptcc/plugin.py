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
        self.addr2cc_info = {}
        self.store = store
        self.init_crypto_identity()

    #
    # muacrypt plugin hook implementations
    #
    @hookimpl
    def process_incoming_gossip(self, addr2pagh, account_key, dec_msg):
        sender_addr = parse_email_addr(dec_msg["From"])
        root_hash = dec_msg["GossipClaims"]
        store_url = dec_msg["ChainStore"]
        self.register_peer(sender_addr, root_hash, store_url)

        store = FileStore(store_url)
        peers_chain = Chain(store, root_hash=ascii2bytes(root_hash))
        recipients = get_target_emailadr(dec_msg)
        for addr in recipients:
            pagh = addr2pagh[addr]
            value = self.read_claim(addr, chain=peers_chain)
            if value:
                assert value['key'] == bytes2ascii(pagh.keydata)
                # TODO: check for existing entries
                if value['store_url']:
                    self.register_peer(addr, value['root_hash'], value['store_url'])

    @hookimpl
    def process_before_encryption(self, sender_addr, sender_keyhandle,
                                  recipient2keydata, payload_msg, _account):
        addrs = recipient2keydata.keys()
        if not addrs:
            logging.error("no recipients found.\n")

        for addr in addrs:
            self.add_claim(self.claim_about(addr, recipient2keydata.get(addr)))

        for reader in addrs:
            if self.can_share_with(reader):
                self.share_claims(addrs, reader)

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

    def register_peer(self, addr, root_hash, store_url, pk=None):
        if not pk:
            store = FileStore(store_url)
            chain = Chain(store, root_hash=ascii2bytes(root_hash))
            assert chain
            view = View(chain)
            pk = view.params.dh.pk
        assert pk
        self.addr2cc_info[addr] = dict(
            root_hash=root_hash,
            store_url=store_url,
            public_key=pk
        )

    def claim_about(self, addr, keydata):
        info = self.addr2cc_info.get(addr) or {}
        content = dict(
            key=bytes2ascii(keydata),
            store_url=info.get("store_url"),
            root_hash=info.get("root_hash")
        )
        return (addr, content)

    def commit_to_chain(self):
        chain = self._get_current_chain()
        with self.params.as_default():
            self.head = self.state.commit(chain)

    def read_claim(self, claimkey, chain=None):
        if chain is None:
            chain = self._get_current_chain()
        try:
            with self.params.as_default():
                value = View(chain)[claimkey.encode('utf-8')]
                return json.loads(value.decode('utf-8'))
        except (KeyError, ValueError):
            return None

    def add_claim(self, claim):
        key = claim[0].encode('utf-8')
        value = json.dumps(claim[1]).encode('utf-8')
        assert isinstance(key, bytes)
        assert isinstance(value, bytes)
        self.state[key] = value
        with self.params.as_default():
            self.state.grant_access(self.get_public_key(), [key])

    def can_share_with(self, peer):
        reader_info = self.addr2cc_info.get(peer) or {}
        return bool(reader_info.get('public_key'))

    def share_claims(self, claim_keys, reader):
        claim_keys = [key.encode('utf-8') for key in claim_keys]
        reader_info = self.addr2cc_info.get(reader) or {}
        pk = reader_info.get("public_key")
        assert pk
        with self.params.as_default():
            self.state.grant_access(pk, claim_keys)

    def _get_current_chain(self):
        return Chain(self.store, root_hash=self.head)
