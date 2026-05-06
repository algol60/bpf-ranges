#!/usr/bin/python

# Requires "dnf install python3-bcc".
#
from bcc import BPF

from pathlib import Path
import sys

# The bcc library is installed by the system, so we can only use the built-in python.
#
if sys.executable != '/usr/bin/python':
    print('Use the system Python at /usr/bin/python')
    sys.exit(1)

# TODO read this from a file.
#
CONFIG = {
    'frogger': (9000, 9009),
    'dev99': (9010, 9019)
}

BPF_OBJ_PATH = Path(__file__) / 'port_restrict.o'

# Attach to this cgroup; root cgroup for system-wide enforcement).
#
CGROUP_PATH = '/sys/fs/cgroup'

class PortRestrictor:
    def __init__(self):
        self.b = None

    def load_bpf(self):
        """Load the BPF programs."""

        with open(BPF_OBJ_PATH, 'rb') as f:
            bpf_code = f.read()

        self.b = BPF()

    def populate_user_map(self):
        user_port_map = self.b['user_port_map']
        print(user_port_map)
