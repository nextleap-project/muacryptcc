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
from .commands import cc_status, cc_sync

hookimpl = pluggy.HookimplMarker("muacrypt")


@hookimpl
def add_subcommands(command_group):
    command_group.add_command(cc_status)
    command_group.add_command(cc_sync)


@hookimpl
def instantiate_account(plugin_manager, basedir):
    basename = os.path.basename(basedir)
    plugin_name = "ccaccount-" + basename

    # avoid double registration
    p = plugin_manager.get_plugin(name=plugin_name)
    if p is not None:
        plugin_manager.unregister(name=plugin_name)

    cc_dir = os.path.join(basedir, "muacryptcc")
    store_dir = os.path.join(cc_dir, "store")
    store = FileStore(store_dir)
    cc_account = CCAccount(cc_dir, store)
    plugin_manager.register(cc_account, name=plugin_name)


class CCAccount(object):
    def __init__(self, accountdir, store=None):
        self.accountdir = accountdir
        if not os.path.exists(accountdir):
            os.makedirs(accountdir)
        self._addr2cc_info = {}
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

        peers_chain = self.get_chain(store_url, root_hash)
        recipients = get_target_emailadr(dec_msg)
        for addr in recipients:
            pagh = addr2pagh[addr]
            self.verify_claim(peers_chain, addr, pagh.keydata)
            self.register_peer_from_gossip(peers_chain, addr)

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
        if self.head:
            return bytes2ascii(self.head)

    def register_peer(self, addr, root_hash, store_url, chain=None):
        # TODO: check for existing entries
        if not chain:
            chain = self.get_chain(store_url, root_hash)
        assert chain
        view = View(chain)
        pk = view.params.dh.pk
        assert pk
        self._addr2cc_info[addr] = dict(
            root_hash=root_hash,
            store_url=store_url,
            public_key=pk
        )

    def get_peer(self, addr):
        return self._addr2cc_info.get(addr) or {}

    def get_chain(self, store_url, root_hash):
        store = FileStore(store_url)
        return Chain(store, root_hash=ascii2bytes(root_hash))

    def verify_claim(self, chain, addr, keydata, store_url='',
                     root_hash=''):
        autocrypt_key = bytes2ascii(keydata)
        claim = self.read_claim(addr, chain=chain)
        if claim:
            assert claim['autocrypt_key'] == autocrypt_key
            if store_url:
                assert claim['store_url'] == store_url
            if root_hash:
                assert claim['root_hash'] == root_hash

    def register_peer_from_gossip(self, chain, addr):
        value = self.read_claim(addr, chain=chain)
        if value and value['store_url']:
            self.register_peer(addr, value['root_hash'], value['store_url'])

    def claim_about(self, addr, keydata):
        info = self.get_peer(addr)
        content = dict(
            autocrypt_key=bytes2ascii(keydata),
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

    def can_share_with(self, peer):
        reader_info = self.get_peer(peer)
        return bool(reader_info.get('public_key'))

    def share_claims(self, claim_keys, reader):
        claim_keys = [key.encode('utf-8') for key in claim_keys]
        reader_info = self.get_peer(reader)
        pk = reader_info.get("public_key")
        assert pk
        with self.params.as_default():
            self.state.grant_access(pk, claim_keys)

    def _get_current_chain(self):
        return Chain(self.store, root_hash=self.head)
