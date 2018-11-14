# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
import os
from test_muacrypt.test_account import gen_ac_mail_msg
from muacrypt.account import Account
from muacryptcc.plugin import CCAccount
from muacryptcc.filestore import FileStore


def test_no_claim_headers_in_cleartext_mail(account_maker):
    acc1, acc2 = account_maker(), account_maker()

    msg = send_mail(acc1, acc2)
    assert not msg['GossipClaims']
    assert not msg['ClaimStore']


def test_claim_headers_in_encrypted_mail(account_maker):
    acc1, acc2 = account_maker(), account_maker()
    send_mail(acc1, acc2)

    dec_msg = send_encrypted_mail(acc2, acc1)[1].dec_msg
    assert dec_msg['GossipClaims']
    assert dec_msg['ClaimStore']


def test_claims_contain_keys_and_cc_reference(account_maker):
    acc1, acc2 = account_maker(), account_maker()
    send_mail(acc1, acc2)
    send_encrypted_mail(acc2, acc1)
    dec_msg = send_encrypted_mail(acc1, acc2)[1].dec_msg
    assert dec_msg['GossipClaims']
    assert dec_msg['ClaimStore']


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
       Decrypt and process it.
       Returns the result of processing the Autocrypt header
       and the decryption result.
    """
    if isinstance(recipients, Account):
        recipients = [recipients]
    msg = gen_ac_mail_msg(sender, recipients, payload="hello", charset="utf8")
    enc_msg = sender.encrypt_mime(msg, [r.addr for r in recipients]).enc_msg
    for rec in recipients:
        processed = rec.process_incoming(enc_msg)
        decrypted = rec.decrypt_mime(enc_msg)
    return processed, decrypted
