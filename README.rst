muacrypt ClaimChains plugin
===========================

MuacryptCC provides consistency checks
for keys observed in Autocrypt gossip
to support privacy-preserving decentralized key distribution.
The underlying concept is descript in
`Key consistency with ClaimChains <https://countermitm.readthedocs.io/en/latest/claimchains.html>`_.

It's build on top of `ClaimChain <https://claimchain.github.io/>`_.
These hash chains store claims about public keys
that people use and have observed.

It uses email headers to transfer
references to the chains of the sender and recipients.
The chains themselves are uploaded to and retrieved from an online storage
at message delivery and retrieval times.


installing
----------

Use pip to add the muacryptcc plugin::

    $ pip install --user muacryptcc

MuacryptCC will install muacrypt and extend the installation.
You can confirm it was properly installed by running::

    $ muacrypt cc-status


testing
-------

Please follow the `muacrypt <https://github.com/hpk42/muacrypt>`_
instructions for testing first.

Once muacrypts tests are passing
Clone the muacryptcc repository into a separate folder::

    $ git clone https://github.com/nextleap-project/muacryptcc

Afterwards you can run all tests::

    $ tox

installation for development
++++++++++++++++++++++++++++

If you plan to work/modify the sources
you will first need a git clone::

    $ git clone git@github.com:nextleap-project/muacryptcc.git
    $ cd muacryptcc

We strongly recommend to create
and activate a python virtualenv
and then once use
**pip without sudo in edit mode**::

    $ virtualenv venv
    $ source venv/bin/activate
    $ pip install -e .

If you want to make changes to both muacrypt and muacryptcc
we recommend setting up a virtualenv
with both directories installed in edit mode::

    $ virtualenv venv
    $ source venv/bin/activate
    $ pip install -e ../muacrypt
    $ pip install -e .

Changes you subsequently make to the sources
will be available without further installing the packages again.

Next Steps
----------

We envision the following next steps
to make MuacryptCC check the consistency guarantees
between peer chains:

- online block store to allow remote access to peers chains.
- subcommand to list conflicts in chains retrieved so far.
- subcommand to display ordered list of recommended key verifications.
