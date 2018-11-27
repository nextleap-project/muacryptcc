0.9.0 - use online storage to exchange claims
---------------------------------------------

Support exchanging claims via cchttpserver.

This release introduces the cc-send command.
It will upload the local claim chain to a remote cchttpserver.

FileStore now takes the url of a remote cchttpserver as an argument.
When claims are not available locally it will look them up remotely.
This way it acts as a transparent cache when reading peers claim chains.

- use cc_account.upload() in the cc-send command

- explicitly call cc.upload() to upload new blocks

- reuse the existing plugin, when initialization happens twice
  unregistering the old and registering a new plugin might
  cause problems if the old CC account is still used somewhere.

- cc-status: print some more details

- filestore: recv missing data from remote
  This way we can easily integrate it with claimchain.
  For other peoples chains the store basically acts as a local cache.

- enable FileStore to sync to a remote cchttpserver

- use devpi-index for getting latest "muacrypt"

- use muacrypt's command line structure
  where accounts are always specified via "-a ACCOUNTNAME"
  and default to "default"

- rename cc-sync to cc-send and make it accept a URL

- fix str/bytes issues


0.8.1 and 0.8.2
----------------------------------------

- fix some packaging issues

0.8.0 - assert Autocrypt key consistency
----------------------------------------

Initial release.

This is the first release that can be used in production
to verify consistency of the keys observed.
It will persist a log about them
and raise assertion errors in case of inconsistent keys.

MuacryptCC is established as a plugin to Muacrypt.
It makes use of hooks into muacrypt.

This release does not yet allow retrieving chains from peers
as it relies on local files as a chain store.

This release provides the following:

- use own claimchain to store info about peers
  including the public dh key for their claimchain.

- implement CCAccount to handle all claimchain related operations.
  It abstracts away the detailed calls to add claims and capabilities.
  Instead it operates on concepts like peers and chains.
  It defines the concrete format for claims.

- add initial subcommands to muacrypt

- make use of peer info to add capabilities for peers
  with ClaimChains.

- register peers and store info about them in our own claimchain.

- include head imprints and store urls for ClaimChains of peers
  if available

- add claims according to gossip present in the outgoing mails.

- unit tests for the CCAccount module
  and integration test for the use as a Muacrypt module

- establish internal API for storing and retrieving claims.
  This API can also be used to read claims from other peoples chains
  if the required capabilities are present.

- build test system that includes muacrypt and makes use of it's
  hook system

- Make use of muacrypt hooks to learn about messages received
  and inject claimchain headers into outgoing mails.

We also provided error reports, failing tests and fixes to
claimchain-core and rousseau-chain. Claimchain version 0.2.3
incorporates all fixes.

We rely on hooks provided by Muacrypt version 0.8.0.
MuacryptCC will not be able to register commands with previous versions.

