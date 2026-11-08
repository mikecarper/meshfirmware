#!/usr/bin/env python3
"""Build a small generic recovery package; firmware is selected at runtime."""
import argparse
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    names = ('recover-esp32.sh', 'recover-esp32.cmd', 'ESP32-RECOVERY.md', 'LICENSE',
             'recover-station.sh', 'recover-station.cmd', 'STATION-RECOVERY.md',
             'tools/esp32_recovery.py', 'tools/station_recovery.py', 'tools/meshcore_partition_expansion.py')
    contents = {name:(ROOT/name).read_bytes() for name in names}
    for name in ('recover-esp32.cmd','recover-station.cmd'):
        contents[name] = contents[name].replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
    contents['SOURCE.txt'] = b'Source: https://github.com/mikecarper/meshfirmware\nNo firmware images are bundled.\n'
    contents['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(contents.items())).encode('ascii')
    with zipfile.ZipFile(args.output,'w',compression=zipfile.ZIP_DEFLATED) as bundle:
        for name,data in sorted(contents.items()):
            info=zipfile.ZipInfo('ESP32-Recovery/'+name,date_time=(2026,11,8,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.create_system=3
            info.external_attr=(0o100755 if name.endswith('.sh') else 0o100644)<<16
            bundle.writestr(info,data)
    print(str(args.output)+'\nSHA256 '+hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__=='__main__':
    main()
