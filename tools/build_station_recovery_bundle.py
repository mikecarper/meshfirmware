#!/usr/bin/env python3
"""Package source, notices and hash-verified published Station recovery images."""
import argparse
import hashlib
from pathlib import Path
import zipfile

import station_recovery as recovery

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware-dir', required=True, type=Path,
                        help='Published merged images and matching meshtext-license.txt files')
    parser.add_argument('--meshcore-license', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    contents = {p: (ROOT / p).read_bytes() for p in (
        'recover-station.sh', 'recover-station.cmd', 'STATION-RECOVERY.md', 'LICENSE',
        'tools/station_recovery.py', 'tools/meshcore_partition_expansion.py',
        'docs/test-results/station-recovery-2026-11-08.md')}
    contents['LICENSE-MeshCore.txt'] = args.meshcore_license.read_bytes()
    contents['SOURCE.txt'] = (
        'Recovery script source: https://github.com/mikecarper/meshfirmware\n'
        'Firmware source: https://github.com/mikecarper/MeshCore/tree/03214a16\n'
        'Firmware release: https://github.com/mikecarper/MeshCore/releases/tag/full-profiles-'
        + recovery.RELEASE + '\n').encode('ascii')
    for target, digest in recovery.IMAGES.values():
        stem = target + '-full-usb-wifi-ota-' + recovery.RELEASE
        blob = (args.firmware_dir / (stem + '-merged.bin')).read_bytes()
        recovery.validate_image(blob, digest)
        contents['firmware/' + stem + '-merged.bin'] = blob
        contents['firmware/' + stem + '.meshtext-license.txt'] = (
            args.firmware_dir / (stem + '.meshtext-license.txt')).read_bytes()
    contents['recover-station.cmd'] = contents['recover-station.cmd'].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    contents['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'
                                    for name, data in sorted(contents.items())).encode('ascii')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in sorted(contents.items()):
            info = zipfile.ZipInfo('Station-Recovery/' + name, date_time=(2026, 11, 8, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100755 if name.endswith('.sh') else 0o100644) << 16
            bundle.writestr(info, data)
    print(args.output)
    print('SHA256 ' + hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
