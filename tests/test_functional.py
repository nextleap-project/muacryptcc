# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab

from __future__ import unicode_literals
from test_muacrypt.test_account import gen_ac_mail_msg


def test_encrypt_decrypt_mime_text_plain(account_maker):
    acc1, acc2 = account_maker(), account_maker()

    # send a mail from addr1 with autocrypt key to addr2
    msg = gen_ac_mail_msg(acc1, acc2)
    r = acc2.process_incoming(msg)
    assert r.peerstate.addr == acc1.addr

    # send an encrypted mail from addr2 to addr1
    msg2 = gen_ac_mail_msg(acc2, acc1, payload="hello ä umlaut", charset="utf8")
    r = acc2.encrypt_mime(msg2, [acc1.addr])
    acc1.process_incoming(r.enc_msg)

    # decrypt the incoming mail
    r = acc1.decrypt_mime(r.enc_msg)
    dec = r.dec_msg
    assert dec.get_content_type() == "text/plain"
    assert dec.get_payload() == msg2.get_payload()
    assert dec.get_payload(decode=True) == msg2.get_payload(decode=True)
