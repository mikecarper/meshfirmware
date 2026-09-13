#!/usr/bin/env bash
# Fake venv Python for the dependency launcher; never installs or opens USB.
[[ "$#" == 4 && "$1" == 'helper with spaces.py' && "$2" == dependencies \
    && "$3" == --install && "$4" == --text ]] || exit 99
echo 'meshcore: installed 2.3.9.1; API OK'
exit "${MESHFIRMWARE_TEST_DEPENDENCY_EXIT:-0}"
