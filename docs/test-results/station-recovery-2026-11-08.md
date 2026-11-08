# Station USB recovery validation - 2026-11-08

The new settings-preserving recovery path passed on a physical Station G2.
The board started on `v1.18.0.2-halo-keymind-cascade-dev-observer-ba0321a8`.
The tool installed the published Full Repeater
`v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16` recovery image, verified
its writes, used the native USB forced-download clear/watchdog reset, and
confirmed the running version and board through USB CLI replies.

Independent before/after CLI checks confirmed the same public identity, node
name, radio settings, TX setting and repeating setting. The tool verified
unchanged partition-table and NVS bytes before resetting. Its preservation
write ranges exclude SPIFFS and app1; host tests also check sector erase bounds.

After the test, the original bootloader and application selection were restored.
The original version, identity and checked settings matched, and the original
MQTT service was restarted. Private serial logs remain on the test host.

Host regressions cover all four pinned board/role selections, image integrity,
wrong chip/capacity/USB identity, old/damaged layouts, explicit factory erase,
application/bootloader/selection ordering, retained data, interrupted writes,
masked forced-download clearing, busy ports, USB port renumbering and honest
application-startup confirmation. The release bundle validates all four actual
published merged images and includes their original attribution files.

Limits: no physical G3, Room Server, factory-erase, or deliberately crashing
application test was performed for this tool. Automatic connection was tested
from a running G2. Manual BOOT mode is the fallback when a crashing application
drops USB before automatic bootloader entry can complete. This test does not
identify or fix the reported G3 alpha2 firmware crash.
