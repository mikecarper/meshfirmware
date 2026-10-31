# Browser USB flasher

https://mikecarper.github.io/meshfirmware/

A static GitHub Pages app: it talks directly to the port you select. It does
not launch `firmware.cmd`, contact a localhost service, install Python, or
upload your local firmware, identity, settings or backups. Current public release
firmware is downloaded automatically from a hash-verified mirror on this site;
unmirrored public downloads contact their named hosts. GitHub receives ordinary site requests.

This is a **hardware preview**. Automated protocol, safety, simulated serial,
WebAssembly and simulated IndexedDB persistence tests pass. On 2026-10-29,
one Heltec V4.3 OLED bench radio completed an end-to-end application update
through the published site in desktop Chrome: Meshtastic 2.7.15 detection,
TinyUSB handoff despite a final control-transfer disconnect, explicit same-radio
ROM reselection, MAC/security/partition checks, two-slot writes with matching
target MD5 readback, browser reset, and fresh application-port selection.
Startup verification confirmed Companion v1.18.0.1, protocol 14, the
`Heltec V4.3 OLED` model and `storage.layout` after installing the selected
Keymind Cascade Full Companion OLED application. No partition expansion was
needed. An existing private 16 MiB raw backup was retained, and the browser's
skip-backup option was explicitly selected; this run did not qualify browser
configuration backup or restore.

That result qualifies this one Chrome/V4 application-update path, not all
hardware or operations. Browser end-to-end flashing on other boards, nRF52
flashing, erase/new installs, partition migration and browser crash/reload
recovery persistence remain unverified. Start with a recoverable bench radio,
not a remote USB-only node.

## Use

The USB button, firmware/hardware/role/version/build selectors, and Prepare/Flash
actions are at the top. Buttons and user actions are left-aligned, including
advanced tools, backup/restore, console commands and confirmation dialogs.
Large numbers mark the main actions: **1 Choose USB port**, **2 Update or Erase &
new install**, **3 Backup & prepare**, **4 Review & flash**, **5 Verify running
application**. Step 5 is an optional secondary action immediately right of button
4 in the main action row, not under Advanced options. It remains disabled until
startup verification is pending and an application port is selected; a pending ESP32 reset must finish
first. Backup & prepare is
a dark primary button, matching USB selection and Flash. The installation
choices share one numbered, accessible radio group—not another action button.
The next-step hint follows the current stage. The next required control has an
amber outline, and the next button also shows **Next**, including USB selection
after a DFU reconnect. Newly required controls are revealed and scrolled into
view when needed, including connection controls lower on the page. Repeated
updates do not keep moving the page; reduced-motion preferences are respected.
This is guidance only; highlighting never focuses, clicks or runs an action.
If an ordinary bootloader handoff reconnects USB, repeat 1 then 3 for the same
radio. Supported partition expansion instead uses one scoped confirmation for
the bridge and final firmware and continues automatically; only a newly
ungranted USB interface may still require step 1. The numbers never imply that
a backup or application startup was verified.

An ESP32 TinyUSB radio can disconnect while acknowledging the final bootloader
control signal. That final-stage interruption is shown as a pending handoff,
not a failed flash: select the same radio's ROM port with step 1. The selected
image, board and backup decision are retained, and preparation reconnects without
another reset. ROM synchronization must still verify the bootloader. Earlier
control failures and permission/security errors still stop the operation.

After an ordinary completed transfer, **Flash a new device** is the main action;
verification of the previous radio is an optional alternate path. The new-device
button comes first and is highlighted; reconnecting to verify is secondary.
Refreshing restores the same choice with an unfinished startup reminder.
To switch to another radio, click **Flash a new device**, confirm with
the button, then **1 Choose USB port**. This dismisses only the previous radio's
startup reminder and clears its image, identity and selections; its startup is
still unverified. No radio is reset or written, and downloaded backups are kept.
An unfinished write, reset, migration or recovery must be resolved first; this
action cannot discard those records.

The **Installation** switch defaults to **Update** (unless explicitly selected
by a shared link) and filters the build list.
**Erase & new install** selects merged ESP32 installations, or validates a
separate erase ZIP before an nRF52 application install. It warns about identity
and settings loss; selecting the mode never resets, downloads or flashes a node.
Changing mode discards the previous prepared image, write plan and backup approval.
Pending recovery/migration/verification keeps its original image and locks the
switch. Erase mode is not saved as a preference for the next page visit.
Advanced options, backup/restore, the console and help
start collapsed. Required recovery, migration, connection or archive controls
open automatically when needed; warnings, progress and final confirmations stay
visible. The top navigation opens the corresponding tools without touching USB.

### Shared selection links

Choose any board and use **Copy selection link** beside the firmware-file links.
It works without USB access, including on a phone. The link follows the current
provider, hardware, role and installation mode. With no build selected, empty
version/build filters stay unpinned; selecting a public build pins its exact
provider, board, role, version and filename. Local firmware files are never
included. If clipboard access is unavailable or denied, a read-only text box
shows the link for manual copying. Sharing does not include device identity,
settings, backup data, USB permission or write approval.

URL query parameters can preselect the catalog after it loads:

```text
https://mikecarper.github.io/meshfirmware/?provider=Keymind%20Cascade&hardware=Heltec%20T114&role=companionFull&mode=update#firmware-choices
```

Supported parameters:

| Parameter | Value |
| --- | --- |
| `provider` | Exact firmware provider, such as `Keymind Cascade` or `MeshCore` |
| `hardware` | Exact hardware label, such as `Heltec T114` |
| `role` | Exact role, such as `companionFull` or `repeater` |
| `version` | Exact catalog version; omit to show all available versions |
| `mode` | `update` or `install` (Erase & new install) |
| `build` | Exact firmware filename; selected only when one matching build is visible |

Encode spaces and other special characters in parameter values. Linked
selections take precedence over saved browser choices; omitted filters start
empty, with Keymind Cascade as the default provider. Unsupported, repeated,
empty or unavailable values are ignored. An unavailable filter prevents an
exact build selection. Omit `version` for a link that remains useful as releases
change, or include both `version` and `build` to identify a particular artifact.
The `#firmware-choices` fragment opens the selection section.

These links select catalog options only. They do not download firmware,
request a USB port, reset a radio or authorize a write. Existing pending
recovery, migration or startup verification takes precedence over URL
selections. The usual backup, device checks and flash confirmation still apply.

### Flashing

1. Open the page in desktop Chrome/Edge and choose a USB port. **Automatic setup**
   is on by default: read the running model/role, select matching hardware,
   default to Keymind Cascade and choose its newest write-only application update.
   MeshCore (stock) remains an explicit provider choice; an unavailable Keymind
   build never silently falls back to stock. Saved manual provider choices still work.
   Default Update mode never chooses a wipe or bootloader. Explicit erase mode
   still checks exact board/role/profile compatibility; ambiguous screen/storage
   variants are not guessed. No USB enumeration, reset or flash occurs on page load. Only the
   selected port is queried after permission. Turn off Automatic setup for manual use.
   Meshtastic radios can also be identified through a read-only local device
   report. A reviewed hardware-enum mapping selects the matching MeshCore board;
   for example, a T114 revision 2 selects **Heltec T114**, never **Heltec v2**
   (the unrelated ESP32 board). RAK3401 selects **RAK WisMesh 1W Booster
   (3401 + 13302)** automatically, including the reviewed INFO_UF2 fallback;
   its universal builds do not need a separate carrier/storage selection.
   Detection also reads the local compiled build target (`MyNodeInfo.pio_env`)
   in that same USB identity response. The exact `rak3401-1watt` target resolves
   early RAK3401 images which incorrectly report the RAK4631 enum. Reviewed Wio
   L1 Pro and E-Ink targets similarly resolve the generic L1 enum, including
   E-Ink InkHUD images. The raw enum is retained for diagnostics; a known target
   paired with a conflicting enum stays manual. Remote node records, display
   names, version hashes and similar-looking target names never override it.
   Keymind Repeater defaults to the unified **Full OTA** build when feature
   variants coexist; bridge/reduced builds remain available manually.
   Unknown or ambiguous hardware remains a manual
   choice. This identifies the installed firmware's hardware report, not an
   independent attestation of the physical board. Detection does not reset the
   device, change settings or send a LoRa message. The standard Meshtastic
   configuration response may contain additional records; these are ignored,
   not logged or saved as a backup.
   The probe uses the official serial wake/resynchronization sequence, then
   waits up to 25 seconds for local identity, returning as soon as it arrives.
   Some Meshtastic 2.7.15 native-USB builds can take a full 20-second console
   polling interval to respond. The page shows **Checking MeshCore…** first,
   then **Checking Meshtastic…** with a live seconds counter such as **8s / 25s**.
   The counter uses the actual detection deadline and disappears on success,
   timeout, a disconnected/changed radio or any other detection error. It does
   not add a wait when the node answers quickly.
   Meshtastic's own firmware may temporarily pause Bluetooth while its serial
   API is connected. If USB serial access was disabled in the node's security
   settings, detection cannot override that restriction.

   Equivalent stock/Keymind board names are unified for L1 E-Ink, MeshTracker
   X1 and Solar/P1, including saved choices and older shared links. RAK4631
   also selects its universal family; its default Keymind Repeater is the
   unified Full OTA build. New Solar/P1 and MeshTracker X1 installations prefer
   the Full OTA feature profile when only reviewed same-target Full/Reduced
   choices differ. Meshtastic's reviewed XIAO S3 wiring selects **S3
   WIO**, and its Indicator target selects **Indicator LoRa**. Known factory
   bootloader identities are read-only hints; recognizing DFU does not identify
   a physical board or qualify a replacement bootloader download.

   New Keymind firmware reports Wio L1 Pro, E-Ink and 1W, and Indicator LoRa
   and ESP-NOW, with distinct model names. Older generic model names remain
   manual when those variants cannot be distinguished. Updating that reporting
   does not change radio settings; startup verification accepts the refined name
   only for the selected board and matching pre-update public identity. Distinct
   memory revisions (such as Indicator N16R2) still require an explicit build
   choice unless the running firmware identifies its exact target.
   T-Beam, T3 S3, T-ETH and Muzi Base Meshtastic build targets can each enable
   multiple radio chips at runtime, so their build name alone cannot select a
   MeshCore radio variant. Those hardware/radio choices remain manual.

   When moving from Meshtastic, its local metadata role defaults **Router**,
   **Router Late** and **Client Base** to MeshCore **Repeater**; every other
   role defaults to **Full Companion**. This uses the existing identity query,
   with no extra wait or configuration request. If the default build is
   unavailable, choose a role explicitly; no other role is substituted.
   Keymind is preferred; if that exact board has no Keymind builds, stock can
   be selected instead. Explicit provider/role choices are kept. MeshCore and
   Meshtastic version numbers are not compared as upgrades/downgrades. The page
   does not back up or convert Meshtastic settings, channels or identity: export
   those separately with a Meshtastic client if needed. A clear **Continue to
   MeshCore without backup** choice precedes bootloader entry; no backup is
   claimed and no erase is selected or authorized automatically. Startup
   verification only succeeds when the expected MeshCore application answers.

   If neither application protocol can identify the selected radio, or an
   initially unidentified DFU port is selected, **Read bootloader info** appears
   beside the device summary and is highlighted as the next step. Click it and
   choose that radio's `INFO_UF2.TXT`; the browser requires this fresh file-picker
   permission. A reviewed exact model/Board-ID pair selects matching nRF52
   hardware and a suitable Companion firmware automatically. An ambiguous pair
   shows candidates and leaves the Hardware choice to you. No drive enumeration
   runs in the background, and permission/access failures do not trigger this
   alternate detection path.

   Reading this file never copies firmware to a drive. The file is a board hint,
   not proof that it belongs to the selected USB port or that the port is in DFU.
   Flashing still uses serial DFU, normal compatibility checks and explicit write
   confirmation. Select the same physical radio's DFU serial port; an unlisted
   bootloader may require the explicit **Already in ROM/DFU** choice. File hints
   do not authorize an identity override, recovery or bootloader replacement,
   and they expire when the selected port or operation generation changes. They
   never stand in for an application backup or a startup-verification response.
   Exact `Heltec V4.2 none detected` and `Heltec V4.3 none detected` models are
   recognized as the base V4 running without an attached display. R8, unknown
   revisions and truncated model strings are not guessed. Hardware/provider/role
   are still selected when the node runs a preview newer than the catalog.
   Older compatible firmware is allowed: a downgrade warning shows the running
   and selected versions, including when the newest catalog build is older
   than the node. Backup, compatibility checks and the normal write confirmation
   still apply; downgrading does not bypass any safety check.
2. Check the automatic summary and the visible **Firmware selection** inputs.
   **Firmware files** opens the current public picker for the selected board and
   role; **Download selected build** downloads the exact chosen file/version.
   Both links are beside the build selector and work without a USB connection.
   **Advanced options & troubleshooting → Connection & automatic setup** retains
   connection overrides. Explicit choices are not
   silently substituted. Updated firmware exposes read-only **get usb.mode**;
   the page uses a valid report from the selected responding ESP32 application
   to distinguish hardware USB-Serial/JTAG from TinyUSB, including shared
   `303a:1001` interfaces. When that getter is unavailable, the bundled reviewed
   JSON map matches the **running** hardware, complete version, role and USB ID,
   not the firmware selected for installation. All applicable profiles must
   agree. An explicit live report takes precedence; unknown or conflicting
   historical entries are not guessed.

   Without a valid live **get usb.mode** report, every qualified native ESP32
   connection inferred from the JSON map or older detection is provisional.
   **Backup & prepare** verifies it after backup is considered: first try ROM
   synchronization without reset, then test the recommended USB-JTAG or TinyUSB
   entry method. The other qualified method is tried only after a genuine
   no-response failure on the same still-available endpoint. TinyUSB uses one
   handoff at 115200 followed by no-reset synchronization, never a 1200-baud
   touch. Only a real ROM response verifies the connection; the JSON match alone
   does not. The first working session is retained. These tests never
   erase or write flash, never try UART/nRF52 reset sequences on native ESP32 USB,
   and never run during recovery, migration or startup verification. Permission,
   security, chip or post-sync failures stop the sequence. A new USB interface
   still needs browser permission; no different port is silently substituted.
   Manual connection selection is the final fallback and is scrolled into view.
   Explicit manual overrides remain unchanged. No connection inference bypasses
   backup, chip, board or write confirmation checks.
   Choose **Keymind Cascade** or **MeshCore (stock)**;
   the old separate Logging provider is folded into Keymind Cascade because
   current releases use the same binaries, with runtime logging where supported.
   Duplicate files are removed, distinct historical application builds remain available,
   and saved Logging-provider selections still work. Changing hardware or firmware filters refreshes the
   summary and available files; changing the USB port clears the previous
   automatic board choice before reading the new node. A failed or unknown
   probe cannot leave the old automatic image ready. Changing **Hardware**
   selects a firmware target, not a different USB device—use **Choose USB port**
   to switch connected radios. Deliberately loaded custom files remain clearly
   labelled for manual review, without retaining their old write approval.
   **Custom file or download URL** accepts local
   BIN/DFU ZIP/UF2/release ZIP. If a host blocks browser fetches, use Download,
   then choose that local file. A replacement clears the previous image and
   plan before reading/downloading; a failed replacement cannot leave the old
   image ready to flash.
   Published release-ZIP hashes are checked before indexing; the selected inner
   image is validated separately, never compared to the enclosing ZIP's hash.

   Current GitHub-hosted builds download directly into the flasher from this
   site's verified public firmware mirror. No save-and-reselect step is needed.
   The build verifies each asset against GitHub's uploaded SHA-256 and size;
   the browser verifies the original image again, plus the compressed hash when
   the server exposes compressed bytes rather than HTTP-decoded content.
   Normal container, chip, board, backup and write-confirmation checks still run.
   A corrupt mirror fails closed instead of silently switching sources.

   The mirror is bounded to 850 MiB to stay below GitHub Pages' published-site
   limit. Latest application profiles in both installation modes and recommended
   bootloader/erase/recovery assets take priority; migration archives use remaining
   space. Older, oversized, non-GitHub or custom URLs may not be mirrored. Those
   use their original HTTPS host; if that host blocks browser access (CORS),
   **Download firmware → choose the exact local file** remains the fallback.
   The page never disables CORS, uses an opaque response or uploads private files.
3. Use **Backup & prepare update** (or **Backup & prepare install**): download and validate the selected application, then
   back up before bootloader entry by default. Detection distinguishes a binary
   companion from CommonCLI. Reviewed native USB application reads assert DTR
   at 115200 so older V4 firmware answers; UART and DFU line behavior is unchanged.
   Connection selection handles qualified UART bridges, nRF52 and responding
   TinyUSB applications. TinyUSB entry uses the Arduino control-line sequence
   at 115200, including the Windows DTR-refresh workaround, not a 1200-baud open.
   nRF52 retains its 1200-baud touch. TinyUSB entry is offered after backup; re-select the
   same radio's ROM port and prepare again without choosing a reset strategy.
   The backup window shows validated JSON with **Copy text**, **Stop** and
   **Continue with flashing**. A neutral **Not backed up** list identifies the
   specific excluded or unavailable values in this same window, without a blanket
   partial/incomplete warning or another confirmation prompt. Failed setting reads
   remain identified as failed reads. Continue resumes preparation for the
   normal flash review; it does not write firmware or claim the file was saved.
   The JSON download still starts automatically. Keep the download or copied
   text privately. Failed backups still need separate acknowledgement.
   nRF52 continues directly into serial DFU after backup continuation, without
   another bootloader-entry prompt. Re-select the same radio's DFU port
   when asked; the final flash/wipe and board checks still apply.
   A copy and backup-only button remain available under Backup & restore.
   Lengthy release notes stay in the collapsed **Firmware details** section.
4. Review the exact file, operation, target evidence and hash, then select the
   action-specific confirmation button. No confirmation text needs to be typed.
   An already-running ROM/DFU interface cannot export
   application settings: select **Already in ROM/DFU** and explicitly accept
   continuing without a backup, or return to the application first.

   To deliberately omit step 3, select **Skip backup · go straight to step 4**.
   **Review & flash** downloads, validates and prepares the exact firmware before
   its normal write confirmation, without creating a backup. It does not skip
   chip, board, partition, erase or readback checks. If a USB handoff is needed,
   select the same radio's returning port and use step 4 again. Skipping is off
   by default and is not remembered for an unrelated radio or firmware choice.
   During an active firmware write, a large progress window shows the percentage,
   current stage and file, with a reminder to keep the tab open and power connected.
   The same window includes a live, scrollable console with recent connection
   context and transfer output. It follows new lines while at the bottom;
   scrolling back keeps your reading position. The normal operation log remains
   available after the window closes. Console text is local, bounded and read-only.
   It closes when the write succeeds or fails. The browser's leave-page warning
   is best-effort, not a guarantee against closing the tab or interrupting power.
   During automatic migration, **Stop after this write** stops later steps;
   it does not interrupt the current transfer.
5. ESP32 writes require target MD5 readback before the one-time reset action.
   **Start firmware automatically** is on by default for complete application,
   merged or verified bridge writes, never expert components or failed writes.
   It retains the actual session transport instead of re-guessing USB vs UART.
   After transfer, **Firmware transferred** means the write is finished, but
   application startup has not yet been checked. **Flash a new device** is the
   main next action. To optionally check the previous radio instead, use
   **Verify previous device (optional)** and select the same radio's **APPLICATION**
   USB port, not its DFU/ROM port. Verification then starts automatically; it
   does not flash or reset the radio. **Firmware verified** marks a successful
   startup check, not merely a completed transfer.
   Opening the browser's USB chooser requires a fresh click: the first USB
   selection cannot authorize an automatic chooser popup after a long write.
   When this page previously read the application successfully and knows its
   expected public identity, it remembers that exact application-port object
   and tracks its availability through connection events. After the write or
   **Finish**, it tries startup verification once if that same port is available;
   the identity must match. This read-only attempt never opens a chooser, resets
   or writes. It does not scan or guess from shared USB IDs. An unknown identity,
   different interface or failed attempt leaves **Verify previous device (optional)**
   as an optional secondary path. The successful green **Firmware verified** status
   leaves **Flash a new device** available for the next radio.
   The page checks retained node identity/model when applicable, protected
   nRF52 board family, payload version when verified metadata is available,
   and an ESP32 `get storage.layout` response. **Verify running application**
   retries that check. Transfer completion alone is not startup verification;
   bootloader/SoftDevice-only transfers do not claim application success.

CH340/CP210x/FTDI work through the installed OS serial driver. The page cannot
install drivers or expose device interfaces the browser/OS does not permit.
TinyUSB application handoff and hardware USB-Serial/JTAG remain distinct;
the shared `303a:1001` ID is not used to guess their board or reset mechanism.
Ambiguous IDs, missing models or unknown roles open the manual choices. A missing
application response never proves ROM mode. A newly selected USB interface still
requires browser permission.
Reported firmware models can be wrong if the wrong firmware was installed;
auto-selection is a convenience, not independent physical-board proof. Review
the selected hardware. Existing payload, chip and board checks remain in force.

### If USB disappears during bootloader entry

Pause virtual machines configured for automatic USB capture, or disable the
radio's VM auto-attach rule **before flashing**. The ROM/DFU interface can appear
as a different USB device and be claimed by a guest. Do not assume the VM will
return it after 30 seconds; return it to the host and explicitly select the same
radio. The page cannot reclaim a VM-owned USB device or restart a Windows driver.
Never pause/reset a radio in an active partition-migration bridge just because
USB temporarily disappears; follow its verified completion/recovery workflow.

Older Arduino TinyUSB firmware also has a reported Windows direct-root-port
handoff issue. A USB hub or another socket routed through an internal hub may
help ([Espressif issue](https://github.com/espressif/arduino-esp32/issues/10204)).
On the tested V4, changing from a direct root port to a USB 2.0 socket with an
internal hub, then using the Windows-safe control-line sequence, produced a
verified ROM MAC without an administrator command. VM capture may also have
affected earlier attempts; port routing alone is not proven to be the sole cause.
The browser requires a fresh selected ROM session and chip identity before
writing; no blind retry or 1200-baud fallback follows an uncertain handoff.

## Features and boundaries

| Feature | Browser behavior |
| --- | --- |
| MeshCore / Keymind catalog | Rebuilt daily/on deployment; repository-aware URLs, newest Keymind manifests, primary/proxy/validated-cache fallback, exact-board official utility fallback and newest-first versions; every raw publication route checked in CI |
| ESP32/S2/C3/S3/C6 | Validated application updates and merged installs; chip/security/MAC/capacity and silicon-revision checks; factory-only/non-OTA updates and larger OTA metadata partitions supported |
| Merged ESP32 installs | Populate missing secondary OTA slots from the exact embedded app, with independent readback; refuse ambiguous source boundaries rather than guessing |
| ESP components | Checksum-valid bootloader/component image, explicit address and action-specific button confirmation; never guess an offset |
| nRF52 | Serial DFU like `adafruit-nrfutil`: application, bootloader, SoftDevice or combined SD/bootloader ZIP; guided erase/reconnect/final-write; no mounted-drive workflow or generic Nordic secure-DFU substitution |
| Other UF2 boards | Validated blocks; explicitly chosen bootloader directory and identity recheck; nRF52 UF2 is refused in favor of serial DFU ZIP |
| MeshCore companion backup | Private identity when exposed, channels, contacts, settings, battery/storage and optional CLI snapshots; bounded asynchronous pushes tolerated during contact enumeration; completeness shown separately from integrity |
| MeshCore companion restore | New native-format exports, existing script JSON and legacy browser JSON; exact Python serialization/validation in WASM; model/capacity/key checks, TX/logging readback, deliberate cross-hardware identity replacement |
| Full Companion text mode | Explicit binary handoff; turning USB logging off requires acknowledgement |
| CommonCLI repeater/room | Expanded exposed-settings snapshot, including complete public region trees and policies; Import JSON previews supported settings, then explicitly restores them over the serial console with target checks and readback |
| OS/tool management | Not a browser operation: no pip/driver installs, Raspberry Pi USB-speed changes or shell execution |

Saved settings are verified before the backup is offered. The **Not backed up**
list names firmware/bootloader files, stored messages, runtime logs and any
specific values the firmware did not expose or whose reads failed. It does not
expose secret values or treat companion-only inventories as missing on a repeater.
Archive compatibility/safety flags and flash authorizations are unchanged;
the friendly status describes the verified file, not a promise about uncaptured data.
Imported MeshCore archives
are validated from their original JSON text to preserve Python's canonical
floating-point integrity. Diagnostic firmware versions are never restored.
Known optional CLI settings unsupported by the target produce visible restore
warnings while core settings can still be restored. Unreadable logging state,
transport failures and genuine command errors still stop the restore.
Unstructured optional CLI settings remain available for manual comparison.

Revision-constrained ESP images are checked before erasing or writing. A
mismatch or unavailable required revision needs a separate **Flash despite
revision mismatch** acknowledgement; this never bypasses chip-family, security or flash
bounds checks. Forced transfers still do not prove that the image will boot.

### nRF52 erase and recovery

The normal nRF52 firmware list contains application-only serial DFU ZIPs in
both **Update** and **Erase & new install** modes. Embedded `with-bootloader`
variants are not offered there; bootloader replacement is a separate operation.
Deliberately supplied custom files remain available through **Custom file or
download URL**, with the existing payload, board and destructive-write checks.

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

On a connected nRF52 application with an exact verified board mapping, the page
uses the read-only `get bootloader.ver` response to compare the installed
bootloader with that board's latest stable OTAFIX release. A known older or
preview bootloader offers **Prepare bootloader update** beside the connected
device; a current, newer or custom bootloader does not. Unknown/unsupported
responses, older companion interfaces and DFU-only connections are reported as
unknown, never inferred from application versions, filenames or shared USB IDs.
Reading this status does not reset, enter DFU or write firmware. Preparing an
update opens the separate exact-board bootloader workflow; backup consideration
and explicit flash acknowledgement still apply.

If the current firmware cannot report `bootloader.ver`, install the selected
Keymind application normally first. After its USB application startup is
verified, the page reads `get bootloader.ver` again and asks whether to prepare
the separate update if it now reports an older OTAFIX version or a replaceable
preview. It does not update the bootloader silently, and an unknown response
still does not count as outdated. Declining keeps the running application.
The exact application choice remains selected after a normal bootloader
transfer so it can be reinstalled through the normal same-radio USB handoff,
backup consideration and final write confirmation.

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
additional **Use custom erase utility** acknowledgement, not an automatic trust decision.
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

CommonCLI settings are captured through exposed USB queries and restored through
this page's **Import JSON** flow below. This does not add CommonCLI restore to
`restore.cmd`: the native Python archive's executor flag remains false, and the
browser performs its own reviewed, explicitly confirmed serial operations.
Missing private identity or unavailable required sections cannot become a
complete restore merely because the archive checksum is valid. Files are
downloaded through the browser: the page cannot prove the download reached
disk or set the file permissions, so keep the archive in a private location.
After a validated capture, its exact JSON can also be copied from a read-only
text box in the save-confirmation prompt or under **Backup & restore**. These
copies remain in page memory only, not browser storage, and may contain private
identity and channel secrets. Use **Clear text** to remove the displayed copies;
the prompt's copy is cleared when it closes. Copying is not proof that a private
file was saved, and clearing the text does not recall anything already copied
to the system clipboard or delete a downloaded backup.

### Import JSON and restore repeater settings

Open **Backup & restore → Import JSON**, choose a downloaded script or browser
backup, then select the target radio's application USB port. Importing only
validates the archive and displays a **Restore preview**; it does not open a
serial port or write settings. Review the supported operations and skipped
settings, then press **Review & restore settings** and confirm with the button.
The archive stays on this computer. Firmware versions, partition layout, unread
messages, logs and arbitrary commands embedded in JSON are never restored.

Repeater/CommonCLI backups now read the available core settings plus USB logging,
logging-always/debug, Bluetooth state/name, CAD settings, RX/FEM gain, RX power
saving, display rotation, power saving, and locally exposed administrator,
guest and Wi-Fi credentials. Unsupported or failed queries are identified rather
than silently marked complete. Contact/channel inventories are not applicable
to this role. Complete public region snapshots include hierarchy, flood
permissions (including the wildcard), home and default scope. Regions and a
recognized ACL are merged without deleting unrelated target entries. Old raw
region text and other unstructured snapshots remain available for manual
comparison; no setting absent from the original backup is invented.

New Keymind firmware provides a small, read-only `get config.cap` report for
board/role-specific settings. Backup skips settings confirmed not applicable or
fixed without a readable preference, rather than calling them missing. Readable
diagnostics are still queried and real read failures remain visible. Older or
unrecognized firmware keeps the existing getter probes; missing capability
metadata never implies support or permission to write. The report is preserved
in the JSON without containing setting values or secrets.

Region capture preserves the firmware export's indentation and terminal newline,
checks the complete tree is below its 159-byte truncation boundary, and queries
home/default and individual region records for agreement. Saturated, ambiguous
or unsupported exports remain explicitly incomplete. Private `$` region transport
keys are not exposed by this CLI and are not invented. A new backup is needed
for full region restore when an older JSON contains only the raw tree and no
verified home/default metadata.

Region restore validates names, parents, cycles and the merged map before writes,
creates parents before children, reapplies flood policies after default-scope
selection, saves, and reads the map and selections back. It runs before radio2
settings because a default-scope change can reconcile radio2 automatically.
No interactive `region load`, arbitrary definition text, automatic region
deletion or reboot is used. Large maps that the current firmware cannot export
completely are reported rather than silently restored from truncated text.

Restore uses allowlisted getter/setter pairs, never the archive's command text or
`restore_method` metadata as a script. It checks the selected target's public
identity, role and available board model, probes supported settings before
writing, and reads each applied value back. Unsupported target settings are
reported and skipped; malformed values, rejected commands, transport failures
or changed target identity stop further writes. A restore is not atomic: earlier
settings may already have changed when a later step fails. The report lists
restored, unchanged and skipped items without exposing saved secrets.

**Moving to different hardware** must be selected deliberately; hardware-specific
TX power, gain/CAD, RX power-saving, display and power-saving preferences are
retained on the new board rather than copied blindly. **Explicitly replace the
target identity** is a separate unchecked choice. If CommonCLI accepts a saved
private identity replacement, it is staged until a **manual reboot**; the page
does not reboot the radio or claim the replacement is already active. Reconnect
after reboot and verify the expected identity before using that radio.

New Keymind firmware also exports the saved primary-radio preference through
`get radio.preamble`: `auto` or 8–65528 symbols. Backup preserves it separately
from the radio tuple, and restore uses the existing fifth `set radio` field with
readback verification. CommonCLI keeps the target's primary radio unchanged if
a saved preamble cannot be verified there; unrelated settings can still restore.
Companion reports an unsupported preamble as skipped while retaining its existing
binary core-settings restore. For older CommonCLI backups without this getter,
the preview still warns that the four-field tuple selects **automatic preamble**;
no custom length is invented. Secondary-radio preamble and other settings are
restored only when their saved replies can be parsed and the target supports
them. Firmware/bootloader files, stored messages, runtime logs and values without
an export command are not recreated by a settings restore.

### Settings-preserving partition expansion

The unchanged `tools/meshcore_partition_expansion.py` validator runs inside
Pyodide WebAssembly on demand. Only reviewed exact ESP32/C3/S3 board/role/release
packages qualify. Unsupported layouts/chips do not silently become full wipes.

The page reads the physical table, NVS and OTA state; the exact validator
selects a release-pinned USB-safe middle firmware and binds the plan to the
physical chip MAC and final firmware SHA-256. The public plan and bridge are
persisted in this browser's IndexedDB **before** bridge writes. Raw NVS/OTA
snapshots and private backups are memory-only, not stored in that cache.

For a fresh supported update, **Review & flash** asks once with **Expand & flash
firmware**. This memory-only approval covers the exact chip MAC, bridge, expanded
table, final firmware hashes, required restarts and read-only startup checks.
It automatically writes/verifies the bridge, waits for expansion, verifies the
new table/restoration flags/OTA state, then writes/verifies/restarts the original
final firmware. It applies even if the optional automatic-finish box is off.
Backup save/skip decisions still happen before entering ROM.

Keep power, this tab, browser profile and its storage available. Native USB
bridges return to ROM automatically, always inspected without another reset.
The exact already-selected port resumes on its reconnect event; the page never
scans for or substitutes another radio. If a new USB interface needs browser
permission, choose the same radio with **1 Choose USB port**; no repeated
Prepare/Flash/Reset presses or redundant handoff confirmations are needed.
Classic USB-UART bridges first report the exact MAC-bound settled status,
then automatically re-enter ROM once for final verification and writing.
ESP32-C3/S3 bridges can return to ROM themselves behind a persistent USB serial
adapter; the page waits on that same granted port for up to 180 seconds using
no-reset ROM checks. A newly selected port never inherits automatic reset
permission from the original UART port.

**Stop automatic continuation** stops future stages at a safe boundary; it does
not interrupt an active write. Any failed proof or transport error revokes the
approval without automatically retrying a write/reset. Pending recovery markers
remain. Reloading never restores write authorization; interrupted/resumed
migrations and compatibility overrides use the existing manual checks. After
the final restart, read-only application readiness is retried for up to 120 seconds. Public identity
must match when captured; without it, startup is reported with explicitly
limited identity verification, not proof of the physical application device.

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
**Retry write in chunks** acknowledgement permits 16 KiB writes with independent MD5
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
node scripts/mirror.mjs
pnpm build
node scripts/check-dist.mjs
pnpm preview
```

Only `web/dist` is published. The build copies an explicit runtime/validator
allowlist; an artifact check refuses backup names, credentials, source maps,
symlinks or unexpected root files. The workflow never publishes the repository
root. Runtime dependencies are pinned; third-party licenses ship with the app.
`public/firmware/` is generated and ignored by Git. The mirror builder accepts
only verified assets from explicitly public GitHub repositories, checks both
release metadata and payload bytes, and refuses deployment below 90% current
GitHub-application coverage. Publication checks every mirrored file and keeps
the complete site below 950 MB; no local device files are mirror inputs.
The catalog and its compressed last-known cache contain public release metadata
only. Browser storage is not a substitute for a downloaded private backup.

### Reviewed USB history

`src/data/usb-connection-map.json` is bundled at build time, without an extra
startup download. The checked-in public inventory records exact release
manifests, source revisions, environments and sampled embedded-version evidence.
The generator resolves pinned source build flags and in-repository board
definitions. Missing external board definitions, uncertain primary-console
aliases and unresolved profiles stay explicitly unknown; a missing entry never
authorizes a guessed reset. The initial snapshot retains 2,081 profiles across
14 exact version/source builds, including unknown rows that prevent false
consensus. Existing exact nRF52/UART detection remains independent of this map.

To review and regenerate it, use a MeshCore checkout containing the pinned
source objects (these commands do not build or touch devices):

```sh
node scripts/collect-usb-connection-inventory.mjs --checkout=/path/to/MeshCore --output=scripts/usb-connection-inventory.json
node scripts/build-usb-connection-map.mjs --source-checkout /path/to/MeshCore
node --test test/usb-connection-*.test.js
```

Review changed provenance and unresolved coverage before committing. The normal
site build does not fetch source or regenerate trusted mappings automatically.

References: [official MeshCore flasher](https://github.com/meshcore-dev/flasher.meshcore.io),
[Espressif esptool-js](https://github.com/espressif/esptool-js),
[Web Serial](https://developer.chrome.com/docs/capabilities/serial).
