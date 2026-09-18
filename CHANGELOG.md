# Changelog

All notable changes to **kubuno-p2pnas** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/). Entries are added under
`[Unreleased]` **as the change is made**; `_tools/release.sh` stamps them under the version
number at release time, and CI publishes that section as the GitHub Release notes.

## [Unreleased]

### Fixed

- **The project builds again outside the maintainer's workspace.** Building
  from a fresh clone — which is what CI and any contributor does — failed
  immediately with `failed to load source for dependency kubuno-modauth`, and
  the 0.2.0 tag therefore produced no release artifact at all. The workspace
  manifest redirected the shared Kubuno crates to a sibling checkout of the
  `core` repository, a path that exists only on a machine holding the whole
  workspace. The crates are now resolved solely from their published git tags,
  as in every other Kubuno repository.

## [0.2.0] - 2026-09-18

### Security

- **The node's master key is better protected at rest.** Copies of the key made
  while loading it are now wiped from memory instead of lingering, its directory
  is owner-only, and the node refuses to start if the key file is readable by
  anyone else rather than carrying on silently. The key is also flushed to disk
  on creation, so a crash right after first start can no longer leave a truncated
  key — which would have made every previously stored file unreadable.
- **Peers must now prove who they are.** A peer's identity was simply announced,
  and since those identifiers travel openly on the network, announcing someone
  else's was free — which let an attacker repoint a legitimate peer's address to
  itself and collect every piece of data meant for it. A peer now signs a fresh
  challenge with a key tied to its identity; the key is remembered on first
  contact, and any later handshake presenting a different key (or none) is
  refused without touching anything. Peers running an older version still work
  and are recorded as unproven, so a network can be upgraded progressively.
- **New files are encrypted under a key tied to their owner.** A single key
  protected every user's data on an instance, so isolation between users rested
  entirely on a database filter — one logic slip anywhere and the contents, not
  just the listing, were exposed. New files derive their key from the owner's
  identity as well, and each piece now authenticates which file, which position
  and how many pieces it belongs to: a piece cannot be replayed into another
  file or reordered, and cutting a file short is detected instead of yielding a
  plausible truncated file. Existing files keep decrypting exactly as before.

- **The peer directory can no longer be used to scan a private network.**
  Addresses learned from the discovery network were contacted without any check,
  so a crafted entry could make this node probe a neighbour's router or a service
  on its own machine, and report back whether it answered. Loopback, private,
  link-local, multicast and privileged-port addresses are now refused before
  being learned, contacted or saved.
- **The discovery service is a much poorer amplifier and harder to crowd out.**
  It answered unknown senders in full, which let a forged sender address turn it
  into a traffic reflector; replies to unverified senders are now short and
  challenged. Its address book also evicts dead entries and limits how much a
  single source can teach it, so flooding it early no longer freezes its view of
  the network. And the local-network announcement filter now matches names
  exactly, closing a trick that let a peer make itself invisible.

- **The module no longer answers cross-origin requests.** A blanket permissive
  CORS policy applied to every route, administration included, announcing that
  any web page could call this API with credentials. The module is only ever
  reached through the core's proxy, never by a browser directly, so the policy
  protected nothing and has been removed.

- **A forged header can no longer impersonate any user, administrators
  included.** The module trusted the `X-Kubuno-User-*` headers outright, so any
  process able to reach its local port could claim to be an admin and read,
  download or delete every user's files and drive all peer and quota controls.
  It now requires the signed, short-lived, module-scoped identity token the core
  mints (`kubuno-modauth`); a forged or replayed header is rejected.
- **A path-traversal in shard handling is closed.** A shard id arrives straight
  from the peer-to-peer wire and was used to build a filesystem path with no
  validation, so a crafted id like an absolute path or one containing `..` let
  an unauthenticated peer read the node's master key (and thus decrypt all data),
  overwrite arbitrary files, or delete them. Shard ids are now strictly validated
  before ever touching a path.
- **A single malicious peer can no longer destroy a file.** The repair path
  rebuilt shards from peer-supplied bytes without verifying them; because erasure
  coding is not error-correcting, one tampered shard silently corrupted the
  rebuild and left the file permanently unreadable. Fetched shards are now
  verified against the manifest hash before use.
- **Hosted shards can only be read or deleted by their owner.** `GetShard` now
  only serves shards actually hosted for a peer (never the node's own), and
  `DeleteShard` — previously unauthenticated — now requires the caller to match
  the recorded owner, so a node that merely learns a shard id can no longer erase
  redundancy.
- **The peer listener is hardened against denial of service.** Concurrent
  connections are capped, idle connections time out instead of pinning memory
  (slow-loris), the accept loop backs off on error, and an unsupported request
  is answered with a fixed message instead of echoing the request back (which
  amplified traffic ~5×).
- **The internal IPC secret is compared in constant time**, closing a timing
  side channel that could reconstruct it byte by byte.
- **Infrastructure secrets no longer risk leaking through `Debug`.** The core
  internal secret, the database password and the database URL are redacted in
  the debug output of the configuration structs.

### Fixed

- **A node now knows how much space it actually uses.** Storage was counted by
  the logical size of each piece, but every piece is a separate file that takes
  up whole disk blocks — so a small file's real footprint was under-counted by
  as much as thirty times. A node could therefore believe it had far more free
  capacity than it did, and accept to host more than it could hold. Accounting
  now rounds each piece up to whole blocks.

### Changed

- **This module now installs as a Kubuno package (`.kbpkg`) only.** Its system
  packages (Debian/RPM and the Windows and macOS installers) are no longer
  built: the module is distributed as one `.kbpkg` per platform (Linux, Windows,
  macOS) that the Kubuno server installs itself — from the admin console, or
  offline with `kubuno modules:install <file>.kbpkg`.
- **The default version history is shorter (three versions instead of ten).**
  For a system whose goal is to spend as little of its hosts' space as possible,
  keeping ten past versions of a frequently-edited file could hold about fifteen
  times its content; three keeps that near five, while still letting you walk
  back a couple of bad saves. Administrators can raise it per instance.

### Added

- **Small files no longer waste space.** Every file, however tiny, was split
  into fourteen pieces, each a separate file taking a whole disk block — so a
  1 KiB file cost about 56 KiB on disk and fourteen index rows. Files under
  256 KiB are now transparently regrouped by a background pass into ~1 MiB
  encrypted containers, cutting that overhead from ~56× to about 1.4× and the
  number of pieces and index rows by roughly a hundred. Deleting a packed file
  stays reversible, and containers that empty out are compacted automatically.
  New admin endpoints `POST /admin/repack/run` and `POST /admin/packs/compact`.

- **The node now backs its own index up to its peers, automatically.** Losing a
  node's disk used to mean losing everything, because the index of where each
  piece of data lives existed only there — the manual export added earlier only
  helped whoever remembered to run it. Once a day the node now seals a snapshot
  of that index under its own key, splits it with the same redundancy as user
  data, and spreads it across its peers, keeping the last seven days. The piece
  names are derived from the node key alone, so a fresh machine holding only that
  key can find them again and rebuild — no prior export, and nothing secret to
  remember beyond the key itself (a couple of peer addresses suffice if the
  database was lost too).

- **Re-uploading a file that has not changed no longer stores it again.** An
  upload identical to what is already there was stored in full as a new version,
  charged to the quota and pushed to peers — so a sync client re-sending
  untouched files could multiply everything held for a user, for no new content
  at all. Identical content is now recognised and skipped.

- **A deleted file is no longer gone.** Deleting a file or a folder now moves it
  to a trash you can restore from, and re-uploading a file keeps the version it
  replaced instead of destroying it. Both are listed and restorable, and are
  reclaimed automatically after 30 days for the trash, 90 days or 10 versions for
  the history — on this node and on the peers holding their pieces. Trashed files
  and old versions still count against your quota, because the space really is in
  use; emptying the trash frees it immediately.

- **Silent disk rot is now detected instead of waiting for a failed read.**
  Shards held on other peers were audited on every pass, but the node's own were
  only checked for existence — a file quietly corrupted on disk was discovered
  when someone tried to open it. A rotating sample of local shards is now
  verified byte for byte (a full cycle each week, without re-reading the whole
  disk), and anything corrupt is rebuilt from redundancy like a normal loss.

- **Space held for a long-absent peer is now gradually reclaimed, reciprocally.**
  A peer that never comes online stops contributing to everyone else's
  durability, yet kept consuming host space forever. Each host now reclaims that
  space on its own, in reversible stages keyed to how long the owner has been
  absent — and stretched by how reliable that owner was, so a good contributor
  keeps its data far longer (the margin). After a grace period nothing is touched
  and no new shards are placed for it; later, only the parity shards are shed
  (the data shards still reconstruct every file, so it stays recoverable); only
  after a very long absence is everything removed. Thresholds are administrator
  settings (grace / parity-reclaim / eviction, in days), clamped into order so a
  misconfiguration can never evict before grace. Every host acts locally on its
  own shards — there is no network command to delete another node's data.

- **A node can now be backed up and restored, so its disk dying no longer means
  losing everything.** The manifest is the only record of where each user's data
  lives, and `identity.key` is the root of every key — until now neither was
  saved anywhere, so a dead node's disk meant total, irreversible loss even
  though most shards still lived on peers. An administrator can now download an
  encrypted cold-storage bundle (`GET /admin/backup`, protected by a passphrase)
  holding the identity plus a consistent manifest snapshot, keep it off the node,
  and restore it onto a fresh machine (`POST /admin/restore`) to recover the
  whole "My Cloud". Restore refuses to run on a node that already holds data, so
  it can never clobber a live one.

### Changed

- **A file's pieces are now spread across failure zones, not just across peers.**
  Placement favoured the nearest peers and only limited how many pieces one peer
  could hold — but the nearest peers are often the same home, the same box, the
  same power strip, so one local outage could take out more pieces than the
  redundancy tolerates. Placement now also limits how many pieces sit in one
  network zone, and prefers the hosts that have proven the most dependable. The
  periodic rebalancing follows the same rule, instead of quietly pulling
  everything back towards the nearest neighbours.

- **Downloading is far faster when peers are slow or offline.** A read waited for
  all fourteen pieces of every chunk although ten are enough to rebuild it, kept
  trying peers already known to be offline, and handled chunks strictly one after
  another — so a single unreachable peer added its timeout to every chunk, adding
  minutes to a large file. Reads now start every fetch at once, stop as soon as
  enough verified pieces have arrived, skip peers known to be down, work on
  several chunks at a time, and give up quickly on a host that does not answer.
  Integrity is unchanged: a piece that does not match its fingerprint is still
  treated as lost and never used.

- **Repairs no longer restart every time a peer is briefly offline.** A peer that
  did not answer at that exact second had everything it held re-replicated
  elsewhere — for machines switched off overnight, that meant re-copying the
  whole network every day, and the returning peer's copies became orphans. A
  shard is now only re-replicated once its host is durably absent, unless the
  file has too little redundancy left to wait, in which case it is repaired at
  once. Repairs also start with the files closest to unrecoverable, and prefer
  the more dependable hosts when choosing where to put a rebuilt piece.

- **Background maintenance keeps itself tidy.** Work abandoned by a crash is
  picked back up instead of being lost forever, finished work and events older
  than 30 days are cleaned up so two ever-growing tables stay bounded, and an
  identical maintenance pass is no longer queued twice when one is already
  waiting.

- **Deleting or overwriting a file now frees the space it used on other peers.**
  Until now only the local copy of a file's shards was freed; the ~10 of 14
  shards placed on peers were never reclaimed, so a host's usage grew with every
  delete and re-upload until the network refused all new placement. Deletes,
  folder deletes, overwrites and account removal now tell the hosting peers to
  drop the shards, with bounded retry for peers that are momentarily offline.
- **Overwriting a file is now crash-safe.** The previous version's shards are
  freed only after the new version is durably committed, so an interrupted
  upload can no longer destroy the version it was replacing.
- **Compressible data now takes less space on hosts.** The storage compression
  level is raised (zstd 1 → 3); the entropy probe still skips incompressible
  data, and previously stored files remain readable.

### Fixed

- **Concurrent uploads can no longer push an account over its quota.** The
  allowance was read, checked, then written back as separate steps, so two
  uploads arriving together both saw room that neither had spent yet and both
  went through. The check and the charge now happen in a single operation, and a
  failed upload gives the reserved space back.
- **A failure to upgrade the index is no longer swallowed.** The manifest adds
  missing columns on open, and any error doing so was indistinguishable from
  "the column is already there". That was not cosmetic: without the integrity
  column, every integrity check would have passed unconditionally, silently.
  Failures are now reported.
- **An unreadable index is no longer reported as "file not found".** A genuine
  read error — corruption, a wrong key, a disk problem — was turned into an empty
  answer, so a damaged manifest looked like an empty account.
- **The documented port was wrong** (3119 instead of 3123).

- **A mismatched user/file pair can no longer delete another user's shards.**
  The internal shard lookup on delete was not scoped to the owning user, so a
  caller invoked with mismatched identifiers could have removed another user's
  shards from the store; the lookup is now user-scoped like the deletion itself.

### Fixed

- **p2pnas no longer queries the server from the sign-in screen.** The host
  loads every module before anyone signs in, so the module asked for the
  connected user's quota while there was no session — a request that could only
  be rejected. It now waits until someone is actually signed in, then checks the
  quota as before.


- **A withdrawn dependency is no longer used.** A crate deep in the tree
  (`spin` 0.9.8, pulled in through the HTTP stack) was yanked by its authors.
  No vulnerability was announced, but a withdrawn crate has no business in a
  release; the lockfile now takes the version that replaced it.
- **The package could not be built where `zip` is absent.** The Windows job of
  the continuous integration has no `zip`, so the Windows package was simply lost
  the first time it was attempted — a script failure, not a build failure. The
  builder now falls back to 7-Zip, then to PowerShell.
### Added

- **This module now ships a `.kbpkg`** — the single package format a Kubuno
  server installs by itself, the same file on Linux, Windows and macOS. It
  carries the same binary, interface and manifest as the system packages,
  arranged the way the server expects to find a module on disk, plus a
  `SHA256SUMS` so a copy carried offline can be checked without the catalogue.
  Nothing changes for existing installations: the `.deb`, `.rpm`, `.exe` and
  `.pkg` are still published, and a catalogue that sees both simply prefers the
  new one. It is also the only format the server can unpack without an external
  tool, which is what makes one-click installation possible away from
  Debian-like systems.
### Fixed

- **A built package could be thrown away instead of published.** The job that
  attaches a package to the release waited ten minutes for another workflow to
  create that release, then gave up with "release never appeared — build.yml
  likely failed". The diagnosis was wrong: on a repository whose `.deb` takes
  longer than ten minutes to build, the release simply did not exist yet, and a
  package that had built perfectly was discarded. The job now creates the release
  itself when it is missing, so it no longer depends on another workflow
  finishing first — which also means this repository, which has no `build.yml`
  at all, can publish its packages for the first time.
