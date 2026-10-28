"""Mac-native recovery driver for the A7M4 fastboot/MODE5 recovery channel.

Reuses the SEALED upstream protocol code (ref/sony-a7m4-custom-firmware, pinned
commit) unchanged — only swaps the Windows `fastboot.exe` for the Mac
`/opt/homebrew/bin/fastboot` and drops the Windows-only hardware mutex.

Step-1 scope: OFFLINE self-test + READ-ONLY on-camera connection check.
NO flash, NO partition dump, NO reboot, NO settings/trigger write here.
A restore (flash) path is intentionally NOT exposed in this file yet; it will be
added as a separate, explicitly-gated step after the read-only channel is proven.

Usage:
  python fastboot_recovery_mac.py self-test        # offline, no camera
  python fastboot_recovery_mac.py check-connection  # camera must already be in fastboot; read-only
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "ref/sony-a7m4-custom-firmware"
sys.path.insert(0, str(UPSTREAM))

from a7m4.transport import Fastboot, parse_partitions  # sealed upstream, unchanged
from a7m4.common import ToolError

MAC_FASTBOOT = "/opt/homebrew/bin/fastboot"
OFFICIAL_602 = ROOT / "local/firmware/a7m4-6.02/BODYDATA.DAT"


class MacAssets:
    """Minimal Assets shim: hand the upstream transport the Mac fastboot binary.

    Only 'bin/fastboot.exe' is resolvable (that is all the read-only transport
    needs); anything else raises, so no Windows resource pack is required.
    """

    def get(self, relative):
        if relative == "bin/fastboot.exe":
            path = Path(MAC_FASTBOOT)
            if not path.is_file():
                raise ToolError("FASTBOOT_MISSING", f"Mac fastboot not found at {MAC_FASTBOOT}",
                                "brew install --cask android-platform-tools")
            return path
        raise ToolError("ASSET_UNSUPPORTED", f"Mac adapter does not provide {relative}")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def self_test():
    """Offline readiness: Mac fastboot runnable + official 6.02 restore image staged.

    Touches no camera. Proves the recovery toolchain is ported and the restore
    ammunition is present before we ever enter fastboot.
    """
    import subprocess
    result = {"camera_io": False}
    # 1. Mac fastboot present and runnable
    fb = MacAssets().get("bin/fastboot.exe")
    out = subprocess.run([str(fb), "--version"], capture_output=True, text=True, timeout=15)
    result["fastboot_path"] = str(fb)
    result["fastboot_version"] = (out.stdout or out.stderr).strip().splitlines()[0]
    # 2. Upstream protocol code imports and parses on Mac (no camera)
    sample = ("nflasha1 00000800 0002f000 raw\n" +
              "".join(f"nflasha{n} {(n+2)*0x10000:08x} 00001000 raw\n"
                      for n in (2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 15, 18, 23)) +
              "nflashaB0 20000000 00002000 raw\nnflashaB1 20002000 00002000 raw\n")
    result["parse_partitions_ok"] = len(parse_partitions(sample)) == 17
    # 3. Official 6.02 restore image staged
    result["official_602_present"] = OFFICIAL_602.is_file()
    if OFFICIAL_602.is_file():
        result["official_602_bytes"] = OFFICIAL_602.stat().st_size
        result["official_602_sha256"] = sha256(OFFICIAL_602)
    result["ready"] = (result["parse_partitions_ok"] and result["official_602_present"])
    return result


def check_connection():
    """READ-ONLY: camera must ALREADY be in fastboot. Enumerate + product + partition table.

    No flash, no dump, no reboot. This is the on-camera proof that the Mac
    recovery channel is live and the camera is recoverable.
    """
    fb = Fastboot(MacAssets())
    identity = fb.select()                       # fastboot devices + getvar product (read-only)
    parts = fb.partitions()                      # oem partition (read-only enumerate)
    return {"camera_io": True, "read_only": True, "identity": identity,
            "partitions": [p.json() for p in parts],
            "partition_count": len(parts)}


def main(argv=None):
    import json
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["self-test", "check-connection"])
    a = p.parse_args(argv)
    fn = {"self-test": self_test, "check-connection": check_connection}[a.action]
    print(json.dumps(fn(), indent=2))


if __name__ == "__main__":
    main()
