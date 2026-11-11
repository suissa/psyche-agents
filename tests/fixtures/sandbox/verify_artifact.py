from __future__ import annotations

import pathlib
import socket
import sys

artifact = pathlib.Path(sys.argv[1])
if artifact.read_bytes() != b"psyche-sandbox-fixture":
    raise SystemExit("candidate bytes did not match the fixture")

try:
    pathlib.Path("/etc/psyche-sandbox-write-test").write_text("unexpected")
except OSError:
    pass
else:
    raise SystemExit("root filesystem unexpectedly allowed writes")

status = pathlib.Path("/proc/self/status").read_text()
cap_eff = next(line for line in status.splitlines() if line.startswith("CapEff:"))
if int(cap_eff.split()[1], 16) != 0:
    raise SystemExit("container retained Linux capabilities")

no_new_privs = next(line for line in status.splitlines() if line.startswith("NoNewPrivs:"))
if no_new_privs.split()[1] != "1":
    raise SystemExit("no-new-privileges was not enforced")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    probe.settimeout(0.5)
    try:
        probe.connect(("198.51.100.1", 80))
    except OSError:
        pass
    else:
        raise SystemExit("container unexpectedly reached an external network")

print("candidate read, rootfs read-only, capabilities dropped, no-new-privileges and network isolation verified")
