"""Verify vTPM sealing actually works on this machine.

Run on the enclave VM, before trusting a fleet node:

    python3 tools/tpm_seal_check.py

tools/sealed_key_test.py covers the logic with a stubbed TPM. This covers the
half that stub cannot: whether the tpm2-tools invocations in lib/sealed_key.py
are correct against real hardware, and whether the policy genuinely binds to
PCR15.

Touches nothing in keys/ — it seals a throwaway secret into a temp directory.
The last check extends PCR15, which is irreversible until reboot, so it is
opt-in:

    python3 tools/tpm_seal_check.py --extend-pcr

Only run that on a node with no keypair yet, or one you are willing to reboot:
extending PCR15 invalidates the sealed KEK until the next boot re-derives it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import sealed_key  # noqa: E402


def _pcr15() -> str:
    out = subprocess.run(["sudo", "tpm2_pcrread", "sha256:15"],
                         capture_output=True, text=True, check=True).stdout
    import re
    match = re.search(r"15\s*:\s*0x([a-fA-F0-9]{64})", out)
    if not match:
        raise SystemExit(f"could not parse PCR15 from:\n{out}")
    return match.group(1).lower()


def main() -> int:
    extend = "--extend-pcr" in sys.argv

    if not sealed_key.enabled():
        print("KEY_SEALING=off — nothing to check. Unset it to test sealing.")
        return 1

    print("1. tpm2-tools and /dev/tpm* reachable ...", end=" ", flush=True)
    if not sealed_key.tpm_available():
        print("NO")
        print("   Install tpm2-tools and confirm the VM has vTPM enabled.")
        return 1
    print("yes")

    print(f"2. PCR15 currently: {_pcr15()}")

    with tempfile.TemporaryDirectory(prefix="tpm-check-") as tmp:
        pub = os.path.join(tmp, "check.pub")
        priv = os.path.join(tmp, "check.priv")
        secret = os.urandom(32)

        print("3. sealing a 32-byte test secret ...", end=" ", flush=True)
        try:
            sealed_key.seal(secret, pub, priv)
        except sealed_key.SealingError as e:
            print(f"FAILED\n   {e}")
            return 1
        print("ok")

        print("4. unsealing it ...", end=" ", flush=True)
        try:
            recovered = sealed_key.unseal(pub, priv)
        except sealed_key.SealingError as e:
            print(f"FAILED\n   {e}")
            return 1
        if recovered != secret:
            print("FAILED\n   unsealed value differs from what was sealed")
            return 1
        print("ok")

        print("5. full private-key envelope ...", end=" ", flush=True)
        enc = os.path.join(tmp, "pk.enc")
        pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + os.urandom(1200) + b"\n-----END-----\n"
        try:
            sealed_key.seal_private_key(pem, os.path.join(tmp, "k.pub"),
                                        os.path.join(tmp, "k.priv"), enc)
            if sealed_key.load_private_key(os.path.join(tmp, "k.pub"),
                                           os.path.join(tmp, "k.priv"), enc) != pem:
                print("FAILED\n   envelope round trip differs")
                return 1
        except sealed_key.SealingError as e:
            print(f"FAILED\n   {e}")
            return 1
        print("ok")

        if not extend:
            print("\nSealing works on this machine.")
            print("The PCR15 binding itself is untested — re-run with --extend-pcr "
                  "on a node you can reboot to confirm it.")
            return 0

        print("6. extending PCR15 and confirming the unseal now FAILS ...",
              end=" ", flush=True)
        subprocess.run(["sudo", "tpm2_pcrextend", f"15:sha256={'ab' * 32}"],
                       capture_output=True, check=True)
        try:
            sealed_key.unseal(pub, priv)
        except sealed_key.SealingError:
            print("ok (correctly refused)")
            print(f"\nPCR15 is now {_pcr15()} — reboot before using this node.")
            return 0
        print("FAILED")
        print("   The secret unsealed after PCR15 changed: the policy is NOT")
        print("   binding. Sealed keys on this node are not protected.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
