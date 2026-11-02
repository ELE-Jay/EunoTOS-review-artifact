# Third-Party Materials in the Review Snapshot

The benchmark tools retain their existing rights. The owner has authorized
publication of this particular anonymous review snapshot; this is not a blanket
open-source license for the full project. Existing third-party licenses and
notices are not replaced by that scope restriction.

## Tenon Runtime Images

The recorded generated-configuration runtime images contain Tenon/Unikraft code
and, for TLSF configurations, the TLSF library. `licenses/` retains the Tenon
Apache and Unikraft notices, the TLSF wrapper notice, and the upstream TLSF
`COPYING`, GPL and LGPL texts. `third_party/` contains public kernel/application
source and the library's original source archive, wrapper and three patches.
No `.git` histories, private model responses, credentials or full private
reproduction bundle are distributed.

TLSF 2.4.6's original `COPYING` explicitly offers LGPL and GPL licensing and
describes a special GPL linking/header exception. The packaging descriptor's
short `LGPL-2.0` label is not the complete upstream license statement. The
upstream texts, including that exception, are supplied unchanged rather than
replaced by a new license invented for this benchmark.

The source archive SHA-256 is:

`43fa1f8e468d39723616b2954dc35c4cc7860fcb05565906fbe6887423a18c74`

The three supplied patches were applied to that archive in a disposable
directory. Their resulting `tlsf.c`, `tlsf.h`, `target.h` and Makefile match the
archived library source tree byte for byte. The patched source is also included.
Kernel and application source pins and compatibility-file hashes are recorded
in `third_party/source-scope.json`. The kernel timer statement and two native
adapter corrections match the identities in the saved build records. These
materials support inspection and modification/relinking; this closeout does not
claim to have rebuilt or tested a relinked executable. Original image bytes are
unchanged. Unused upstream Git submodules are listed separately in the source
scope record rather than silently presented as bundled source; the C runtime
configurations do not enable the omitted Rust component.

For the recorded native build commands, consult the retained `build.json` files.
Rebuilding requires an ARM64 native or corresponding cross-compilation setup
and relocation of those historical paths. It is separate from the documented,
hardware-free result replay. The source mirror of the TLSF wrapper is retained
as files; its local Git placeholder is not presented as an authenticated copy
of the historical library commit.

## Audit Dependency

The included pyelftools dependency retains its own license in
`licenses/pyelftools-LICENSE`. Its exact version appears in `dependencies.json`.
The README replay uses the vendored copy with installed site packages disabled.
