#!/usr/bin/env bash
# Provision the NER TEE (kanon-ner-1) from a fleet-node disk clone. Run as root on
# the node via `az vm run-command` (2026-11-22). Idempotent.
#
# The disk is a byte copy of a k-anon node, so it boots holding that node's
# identity, keys and possibly a previous job's files. Everything node-specific is
# destroyed first, then the node is given the NER role and the pinned skald-fta
# image, and rebooted so PCR15 measures the code it will actually run.
set -euo pipefail
BRANCH="${1:-feat/ner-tee}"
REPO=/home/kanonTEE/P3DX-SE-manager
FTA=ghcr.io/datakaveri/skald-fta@sha256:e0844308e62350d86b12e9a926088bb1f37642e2dab1f6ccbc1ceb1dede20c78
G() { sudo -u kanonTEE git -c safe.directory="$REPO" -C "$REPO" "$@"; }

echo "== 1. stop the inherited service"
systemctl stop enclavemanager.service || true

echo "== 2. destroy inherited key material, identity and job files"
KEYS=$REPO/keys
for f in private_key.pem public_key.pem private_key.enc kek.pub kek.priv tls_cert.pem \
         key_generation.json jwt-response.txt deployment_nonce.txt pcr_values.json \
         code_hash.txt image_hash.txt fta_image_hash.txt; do
  [ -f "$KEYS/$f" ] && { shred -u "$KEYS/$f" 2>/dev/null || rm -f "$KEYS/$f"; }
done
mkdir -p "$KEYS"; chown -R kanonTEE:kanonTEE "$KEYS"; chmod 700 "$KEYS"
rm -rf /tmp/tee_input /tmp/tee_output /tmp/tee_urls "$REPO/tee" "$REPO/tee-snapshot" "$REPO/Bundle/encrypted.json"
rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null
truncate -s 0 /etc/machine-id; systemd-machine-id-setup >/dev/null
hostnamectl set-hostname kanon-ner-1

echo "== 3. code: $BRANCH"
G fetch -q origin "$BRANCH"
G checkout -q -B ner "origin/$BRANCH"
G reset -q --hard "origin/$BRANCH"
echo "   HEAD $(G log -1 --format='%h %s')"

echo "== 4. NER role"
cp "$REPO/enclavemanager.service" /etc/systemd/system/enclavemanager.service
# Scratch tmpfs, as on the fleet nodes: NER payloads and results live in RAM.
sed -e "s/@UID@/$(id -u kanonTEE)/" -e "s/@GID@/$(id -g kanonTEE)/" \
  "$REPO/enclave-scratch.mount" > /etc/systemd/system/enclave-scratch.mount
systemctl enable enclave-scratch.mount >/dev/null 2>&1 || true
mkdir -p /etc/systemd/system/enclavemanager.service.d
rm -f /etc/systemd/system/enclavemanager.service.d/*.conf
cat > /etc/systemd/system/enclavemanager.service.d/ner.conf <<EOF
[Service]
Environment=TEE_ID=ner-1
Environment=NODE_ROLE=ner
Environment=KEY_SEALING=on
EOF
systemctl daemon-reload
systemctl enable enclavemanager.service >/dev/null 2>&1 || true

echo "== 5. pinned skald-fta image"
docker image prune -f >/dev/null 2>&1 || true
docker pull -q "$FTA" >/dev/null && docker image inspect "$FTA" >/dev/null && echo "   present: $FTA"
df -h / | tail -1

echo "== 6. reboot in 5 s (PCR15 is measured once per boot, from the code on disk)"
nohup bash -c "sleep 5; systemctl reboot" >/dev/null 2>&1 &
echo done
