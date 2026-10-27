# Browser USB flasher

https://mikecarper.github.io/meshfirmware/

A static GitHub Pages app: it talks directly to the port you select. It does
not launch `firmware.cmd`, contact a localhost service, install Python, or
upload your firmware, identity, settings or backups. Public firmware/catalog
downloads contact their named hosts. GitHub receives ordinary site requests.

This is a **hardware preview**. Automated protocol, safety, simulated serial,
WebAssembly and simulated IndexedDB persistence tests pass. Physical flashing,
visual browser QA and real-browser persistence have not yet been verified.
Start with a recoverable bench radio, not a remote USB-only node.

## Use

1. Open the page in desktop Chrome/Edge and choose a USB port. Optionally enable
   **Detect board & auto-select after choosing a port**, or click **Detect board
   & select** afterward. Running MeshCore's complete model string selects exact
   matching catalog hardware (including reviewed model aliases), not a firmware
   image. Unknown, truncated or ambiguous models stay manual. Detection only
   queries the selected port; it never enumerates or opens other radios. Without
   the option, choosing a port still sends no application probe.
2. Select a release, an HTTPS URL or a local BIN/DFU ZIP/UF2/release ZIP. If a
   host blocks browser fetches, use Download, then choose that local file. A
   replacement clears the previous image and plan before reading/downloading;
   a failed replacement cannot leave the old image ready to flash.
   Published release-ZIP hashes are checked before indexing; the selected inner
   image is validated separately, never compared to the enclosing ZIP's hash.
3. Choose the correct connection type and use **Back up & inspect**. Before
   resetting an application or entering ROM/DFU, the page offers a backup by
   default. Auto-detection distinguishes a binary companion from CommonCLI.
   Confirm that the downloaded archive was saved; partial/failed backups need
   separate acknowledgement. A backup-only button is also available.
4. Review the exact file, operation, target evidence and hash, then type the
   confirmation token. An already-running ROM/DFU interface cannot export
   application settings: select **Already in ROM/DFU** and explicitly accept
   continuing without a backup, or return to the application first.
5. ESP32 writes require target MD5 readback before the one-time reset action.
   Re-select the application port to run startup verification automatically.
   The page checks retained node identity/model when applicable, protected
   nRF52 board family, payload version when verified metadata is available,
   and an ESP32 `get storage.layout` response. **Verify running application**
   retries that check. Transfer completion alone is not startup verification;
   bootloader/SoftDevice-only transfers do not claim application success.

CH340/CP210x/FTDI work through the installed OS serial driver. The page cannot
install drivers or expose device interfaces the browser/OS does not permit.
TinyUSB application handoff and hardware USB-Serial/JTAG are separate choices;
the shared `303a:1001` ID is not used to guess their board or reset mechanism.
Reported firmware models can be wrong if the wrong firmware was installed;
auto-selection is a convenience, not independent physical-board proof. Review
the selected hardware. Existing payload, chip and board checks remain in force.

## Features and boundaries

| Feature | Browser behavior |
| --- | --- |
| MeshCore / Keymind catalog | Rebuilt daily/on deployment; repository-aware URLs, newest Keymind manifests, primary/proxy/validated-cache fallback, exact-board official utility fallback and newest-first versions; every raw publication route checked in CI |
| ESP32/S2/C3/S3/C6 | Validated application updates and merged installs; chip/security/MAC/capacity and silicon-revision checks; factory-only/non-OTA updates and larger OTA metadata partitions supported |
| Merged ESP32 installs | Populate missing secondary OTA slots from the exact embedded app, with independent readback; refuse ambiguous source boundaries rather than guessing |
| ESP components | Checksum-valid bootloader/component image, explicit address, typed acknowledgement; never guess an offset |
| nRF52 | Serial DFU like `adafruit-nrfutil`: application, bootloader, SoftDevice or combined SD/bootloader ZIP; guided erase/reconnect/final-write; no mounted-drive workflow or generic Nordic secure-DFU substitution |
| Other UF2 boards | Validated blocks; explicitly chosen bootloader directory and identity recheck; nRF52 UF2 is refused in favor of serial DFU ZIP |
| MeshCore companion backup | Private identity when exposed, channels, contacts, settings, battery/storage and optional CLI snapshots; bounded asynchronous pushes tolerated during contact enumeration; completeness shown separately from integrity |
| MeshCore companion restore | New native-format exports, existing script JSON and legacy browser JSON; exact Python serialization/validation in WASM; model/capacity/key checks, TX/logging readback, deliberate cross-hardware identity replacement |
| Full Companion text mode | Explicit binary handoff; turning USB logging off requires acknowledgement |
| CommonCLI repeater/room | Partial read-only snapshot, no automatic restore |
| OS/tool management | Not a browser operation: no pip/driver installs, Raspberry Pi USB-speed changes or shell execution |

Every web backup is deliberately marked **not wipe-safe**. Unexposed secrets,
messages, files, logs and firmware may be absent. Imported MeshCore archives
are validated from their original JSON text to preserve Python's canonical
floating-point integrity. Diagnostic firmware versions are never restored.
Known optional CLI settings unsupported by the target produce visible restore
warnings while core settings can still be restored. Unreadable logging state,
transport failures and genuine command errors still stop the restore.
Unstructured optional CLI settings remain available for manual comparison.

Revision-constrained ESP images are checked before erasing or writing. A
mismatch or unavailable required revision needs a separate **FORCE CHIP
REVISION** acknowledgement; this never bypasses chip-family, security or flash
bounds checks. Forced transfers still do not prove that the image will boot.

### nRF52 erase and recovery

Bootloader recommendations use the latest stable release of our
`mikecarper/Adafruit_nRF52_Bootloader_OTAFIX` fork, refreshed with the catalog
on deployment and daily. Its checksum-verified release manifest supplies exact
MeshCore hardware mappings and serial DFU ZIPs; the page checks the selected
ZIP's published size and SHA-256 before loading. Selecting exact hardware can
populate its single normal bootloader ZIP without choosing an application
artifact. Conflicting storage/board profiles still require an explicit artifact.
Normal physical-board bootloaders are never inferred from DFU USB IDs or similar
board names. Missing, ambiguous or unqualified profiles
have no automatic recommendation. If the latest-release check fails, only a
validated last-known fork snapshot may be retained, with a catalog warning;
old upstream bootloader links are not silently substituted.

These combined SoftDevice/bootloader ZIPs require the exact compatible
application to be reinstalled afterward. Application-owned data is not
guaranteed; back up before DFU. Normal recommendations never select temporary
`R_` recovery builds. The separate **Temporary R_ recovery bridge** picker starts
blank. Optional detection can select a unique reviewed DFU USB hint for the
**currently installed bootloader profile**, never the physical target board.
USB mappings are scoped to the reviewed release and full profile inventory;
shared IDs, unknown releases or unreviewed profiles require manual selection.
Web Serial cannot read USB product names or query a model through Legacy DFU.
If known, enter the exact installed name/profile under **Match installed
bootloader** (for example `GAT562BOOT` or `gat562`). Shared names like `XIAO_DFU`
remain ambiguous unless other reviewed evidence disambiguates them. Contradictory
evidence never chooses a profile. These are selection hints, not proof of the
installed version or physical board, and never load or flash a ZIP automatically.

The latest release's recovery bundle and each inner serial DFU ZIP are checked
against their hashes and inventory before use. If browser downloads are blocked,
use **Download recovery bundle**, choose that exact local bundle, and load the
selected profile again. The normal picker remains independent if recovery
metadata is unavailable; verified cached recovery metadata is labelled as such.
No recovery binaries are hosted on Pages or saved in the public catalog.

Every recognized recovery write requires **RECOVERY &lt;profile&gt;**, followed by
the existing independent board override and destructive-write acknowledgements
when applicable. After transfer, select the same radio's new DFU port and install
the normal bootloader for the actual physical board, then its compatible
application. For a RAK4631 showing `GAT562BOOT`, the first bridge is `gat562`,
not RAK4631. Recovery relaxes on-device board/version guards; do not leave it
installed. Transfer completion is not activation or installed-identity proof.
Existing payload/connected-board checks remain in force.

Choose **Erase, reconnect, then write selected ZIP**. The final firmware and
the selected board's erase ZIP are validated before erase. Use the published
erase choice or its exact local ZIP if browser downloads are blocked. Only
application erase packages qualify; bootloader/SoftDevice components cannot be
used as the guided erase step. Official v6/v7 erase utilities and the five
published QSPI formatters (ThinkNode M1, T-Echo, Wio Tracker L1, XIAO nRF52 and
Nano G2 Ultra) are recognized by their payload hashes even after renaming or
repacking. A name-marked custom eraser requires an
additional **CUSTOM ERASE** acknowledgement, not an automatic trust decision.
Erase packages require destructive acknowledgement even when
their DFU manifest calls them an `application`.

Missing provider erase/bootloader hints use official metadata only for an
exact hardware-name and architecture match. Existing provider hints win;
conflicting official hints or unmatched boards require manual selection.
This also works with validated older catalog caches. Serial DFU waits up to
10 seconds per acknowledgement by default; transport callers can supply a
validated `ackTimeoutMs` instead of relying on short fixed ACK waits.

Protected RAK checks examine embedded payload identity and retained pre-DFU
board evidence, not just filenames. Unknown or conflicting evidence requires
a directional, one-write override. That override is separate from the wipe
acknowledgement; neither is a permanent bypass.

After each reset/handoff, explicitly choose the **same physical radio** and
confirm it. The browser cannot compare physical USB serial numbers. After
erase, the final ZIP remains loaded, but no final write occurs until you
reselect its DFU port, inspect again and confirm the write. Recovery state
records only public filenames/hashes and board hints; if the page reloads,
select the original exact final ZIP. Do not disconnect power during recovery.
Successful final bootloader/SoftDevice transfers also release the pending
recovery state so a subsequent application can be selected. They do not claim
that an application or the new bootloader has started successfully.

### Backup compatibility and physical-target checks

New browser downloads use `org.meshfirmware.meshcore-backup/v1`, the native
script archive format. The exact Python serializer seals the archive inside
WebAssembly; the exact validator verifies it before download. Existing script
archives and older browser-format archives still import into this page.

Web Serial exposes VID/PID and port permission, **not** USB serial/location.
The archive explicitly records `browser-port-permission` attestation and null
physical-identity fields; it never invents a physical serial. Updated
`restore.cmd` can use these companion archives, but prompts for the exact
connected target USB serial. The Python restore helper requires
`--target-serial` for a browser capture; moving to a different model also
requires `--new-hardware`. Hardware, public identity, private-key proof and
explicit identity-replacement checks remain in force.
Valid negative TX powers use signed comparisons against the target maximum.
Legacy browser archives receive contact type, coordinate and path validation
before any restore write, in addition to checksum and identity checks.

CommonCLI captures remain partial and cannot be automatically restored.
Missing private identity or unavailable required sections cannot become a
complete restore merely because the archive checksum is valid. Files are
downloaded through the browser: the page cannot prove the download reached
disk or set the file permissions, so keep the archive in a private location.

### Settings-preserving partition expansion

The unchanged `tools/meshcore_partition_expansion.py` validator runs inside
Pyodide WebAssembly on demand. Only reviewed exact ESP32/C3/S3 board/role/release
packages qualify. Unsupported layouts/chips do not silently become full wipes.

The page reads the physical table, NVS and OTA state; the exact validator
selects a release-pinned USB-safe middle firmware and binds the plan to the
physical chip MAC and final firmware SHA-256. The public plan and bridge are
persisted in this browser's IndexedDB **before** bridge writes. Raw NVS/OTA
snapshots and private backups are memory-only, not stored in that cache.

Keep power, this browser profile and its storage available. The bridge must
finish before the final write. Native USB bridges return to ROM automatically;
select that port with **already in ROM / no reset**. Classic ESP32 USB-UART
bridges must report the exact chip-bound settled status before another reset.
Then the validator checks the new table, restoration flags and OTA state.

If the page closed before starting a verified bridge, choose its original
firmware and ROM port without resetting, then use **Recover verified bridge
start**. The page revalidates the cached package and every on-device bridge
slot before allowing one reset. A partial/mismatched bridge is not reset.
Do not clear browser storage during recovery. Lost power during table rewriting
can still require physical access; there is no atomic/brick-proof claim.

An interrupted bridge write against the unchanged original partition table can
resume its original plan; a completed target layout still needs final migration
verification. An interrupted transfer never clears the pending migration.

### Interrupted ESP writes

After a transport failure, reselect **the same physical device** already in ROM
using **no reset**, then inspect the original image again. The recovery
descriptor binds the chip MAC, image, layout and write ranges. A separate
**RETRY IN CHUNKS** acknowledgement permits 16 KiB writes with independent MD5
readback, for at most three explicitly reselected recovery attempts. It does
not silently choose a port, reset the device or repeat a whole-chip erase.
An uncertain erase completion requires a separately authorized fresh install.
Use **Discard ESP retry record** with **DISCARD RETRY STATE** to clear only the
public browser retry descriptor after an uncertain erase or exhausted retries.
This sends no device commands, changes no on-device bytes and never clears a
pending partition migration. A fresh attempt requires reselection, inspection
and the normal write/wipe acknowledgements again.

## Build and test

Node 24 and pnpm 11.25.0:

```sh
cd web
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
node scripts/catalog.mjs
node scripts/check-catalog.mjs
pnpm build
node scripts/check-dist.mjs
pnpm preview
```

Only `web/dist` is published. The build copies an explicit runtime/validator
allowlist; an artifact check refuses backup names, credentials, source maps,
symlinks or unexpected root files. The workflow never publishes the repository
root. Runtime dependencies are pinned; third-party licenses ship with the app.
The catalog and its compressed last-known cache contain public release metadata
only. Browser storage is not a substitute for a downloaded private backup.

References: [official MeshCore flasher](https://github.com/meshcore-dev/flasher.meshcore.io),
[Espressif esptool-js](https://github.com/espressif/esptool-js),
[Web Serial](https://developer.chrome.com/docs/capabilities/serial).
