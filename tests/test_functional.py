# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import os
from test_muacrypt.test_account import gen_ac_mail_msg
from muacryptcc.plugin import CCAccount
from muacryptcc.filestore import FileStore


def test_no_claim_headers_in_cleartext_mail(account_maker):
    acc1, acc2 = account_maker(), account_maker()

    msg = send_and_process_mail(acc1, acc2)
    assert not msg['GossipClaims']
    assert not msg['ClaimStore']


def test_claim_headers_in_encrypted_mail(account_maker):
    acc1, acc2 = account_maker(), account_maker()

    send_and_process_mail(acc1, acc2)
    dec_msg = send_and_process_encrypted_mail(acc2, acc1).dec_msg
    account = get_cc_account(dec_msg['ChainStore'])
    assert dec_msg['GossipClaims'] == account.head_imprint


# send a mail from acc1 with autocrypt key to acc2
def send_and_process_mail(acc1, acc2):
    msg = gen_ac_mail_msg(acc1, acc2)
    acc2.process_incoming(msg)
    return msg


def send_and_process_encrypted_mail(acc1, acc2):
    """Send an encrypted mail from acc1 to acc2
       Decrypt and process it.
       Returns the decryption result with enc_msg and dec_msg.
    """
    msg = gen_ac_mail_msg(acc1, acc2, payload="hello ä umlaut", charset="utf8")
    enc_msg = acc1.encrypt_mime(msg, [acc2.addr]).enc_msg
    acc2.process_incoming(enc_msg)
    return acc2.decrypt_mime(enc_msg)


def get_cc_account(store_dir):
    """ Retrieve a ClaimChain account based from the give store_dir.
    """
    assert os.path.exists(store_dir)
    store = FileStore(store_dir)
    cc_dir = os.path.join(store_dir, '..')
    assert os.path.exists(cc_dir)
    return CCAccount(cc_dir, store)
