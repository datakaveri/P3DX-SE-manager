#!/usr/bin/env python3
"""Expected code measurement and PCR15 for a commit (2026-11-22).

    python3 tools/expected_pcr15.py [commit]     # default HEAD

Mirrors P3DX_SDK._tracked_code_files / hash_enclave_manager_code exactly: the
files git tracks at that commit, measured types only, sorted, each hashed as
relative path + content. PCR15 after one extend from boot is
sha256(32 zero bytes || code hash). Publish the result as the reference value
(the middleware's fleet-reference.json and config.yml ner_tee.reference).
"""
import hashlib
import subprocess
import sys

SUFFIXES = (".py", ".sh", ".json", ".service", ".md", ".txt", ".yaml", ".yml")


def code_hash(commit: str) -> str:
    names = subprocess.run(["git", "ls-tree", "-r", "-z", "--name-only", commit],
                           capture_output=True, check=True).stdout.decode().split("\0")
    digest = hashlib.sha256()
    for rel in sorted(n for n in names if n and n.endswith(SUFFIXES)):
        mode = subprocess.run(["git", "ls-tree", commit, "--", rel], capture_output=True, check=True).stdout.split()[0]
        if mode == b"120000":  # a symlink is not a regular file on disk either
            continue
        digest.update(rel.encode())
        digest.update(subprocess.run(["git", "show", f"{commit}:{rel}"], capture_output=True, check=True).stdout)
    return digest.hexdigest()


if __name__ == "__main__":
    commit = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    h = code_hash(commit)
    print(f"commit     {subprocess.run(['git', 'rev-parse', '--short', commit], capture_output=True, text=True).stdout.strip()}")
    print(f"code_hash  {h}")
    print(f"pcr15      {hashlib.sha256(bytes(32) + bytes.fromhex(h)).hexdigest()}")
