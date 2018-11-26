# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
from test_muacrypt.test_account import gen_ac_mail_msg
from muacrypt.account import Account
from muacryptcc.filestore import FileStore
from claimchain.utils import ascii2bytes


def get_cc_account(account):
    plugin_name = "ccaccount-" + account.name
    cc_account = account.plugin_manager.get_plugin(name=plugin_name)
    return cc_account


def test_no_claim_headers_in_cleartext_mail(account_maker):
    acc1, acc2 = account_maker(), account_maker()

    msg = send_mail(acc1, acc2)
    assert not msg['GossipClaims']
    assert not msg['ClaimStore']


def test_claim_headers_in_encrypted_mail(account_maker, tmpdir):
    acc1, acc2 = account_maker(), account_maker()
    send_mail(acc1, acc2)

    pah, dec_msg = send_encrypted_mail(acc2, acc1)
    cc2 = get_cc_account(acc2)
    root_hash = dec_msg['GossipClaims']
    url = dec_msg['ClaimStore']
    assert root_hash == cc2.head_imprint
    assert cc2.read_claim(acc1.addr)
    store = FileStore(str(tmpdir), url)
    assert store[ascii2bytes(root_hash)]


def test_claims_contain_keys_and_cc_reference(account_maker, tmpdir):
    acc1, acc2 = account_maker(), account_maker()
    send_mail(acc1, acc2)

    pah_from_2, msg_from_2 = send_encrypted_mail(acc2, acc1)
    cc2 = get_cc_account(acc2)
    url2 = msg_from_2['ClaimStore']

    pah_from_1, msg_from_1 = send_encrypted_mail(acc1, acc2)
    root_hash1 = msg_from_1['GossipClaims']
    url1 = msg_from_1['ClaimStore']

    chain = cc2.get_chain(url1, root_hash1)
    assert cc2.read_claim(acc2.addr, chain=chain)
    cc2.verify_claim(chain, acc2.addr, keydata=pah_from_2.keydata,
                     store_url=url2,
                     root_hash=cc2.head_imprint)


def test_gossip_claims(account_maker):
    acc1, acc2, acc3 = account_maker(), account_maker(), account_maker()
    send_mail(acc1, acc2)
    send_mail(acc1, acc3)
    send_encrypted_mail(acc2, acc1)
    send_encrypted_mail(acc3, acc1)
    send_encrypted_mail(acc1, [acc2, acc3])


def test_reply_to_gossip_claims(account_maker):
    acc1, acc2, acc3 = account_maker(), account_maker(), account_maker()
    send_mail(acc1, acc2)
    send_mail(acc1, acc3)
    send_encrypted_mail(acc3, acc1)
    send_encrypted_mail(acc2, acc1)
    send_encrypted_mail(acc1, [acc2, acc3])
    send_encrypted_mail(acc3, [acc1, acc2])


def test_ac_gossip_works(account_maker):
    acc1, acc2, acc3 = account_maker(), account_maker(), account_maker()
    send_mail(acc3, acc1)
    send_mail(acc2, acc1)
    send_encrypted_mail(acc1, [acc2, acc3])
    send_encrypted_mail(acc3, [acc1, acc2])


# send a mail from acc1 with autocrypt key to acc2
def send_mail(acc1, acc2):
    msg = gen_ac_mail_msg(acc1, acc2)
    acc2.process_incoming(msg)
    return msg


def send_encrypted_mail(sender, recipients):
    """Send an encrypted mail from sender to recipients
       upload the new cc blocks,
       Decrypt and process it.
       Returns the result of processing the Autocrypt header
       and the decryption result.
    """
    if isinstance(recipients, Account):
        recipients = [recipients]
    msg = gen_ac_mail_msg(sender, recipients, payload="hello", charset="utf8")
    enc_msg = sender.encrypt_mime(msg, [r.addr for r in recipients]).enc_msg
    get_cc_account(sender).upload()
    for rec in recipients:
        pah = rec.process_incoming(enc_msg).pah
        dec_msg = rec.decrypt_mime(enc_msg).dec_msg
    return pah, dec_msg
