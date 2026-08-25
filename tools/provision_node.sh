#!/usr/bin/env bash
#
# Build one TEE fleet node, from snapshot to attested-and-sealed.
#
#   tools/provision_node.sh 2            # creates kanon-tee-2 as tee-2
#   tools/provision_node.sh 3 --no-seal  # build only; seal later
#
# Run from a workstation with `az` logged in and SSH access. Idempotent enough
# to re-run after a failure: existing disks/VMs are reused rather than
# duplicated.
#
# The step ORDER here is not arbitrary — two orderings are load-bearing and both
# cost real debugging time to discover:
#
#   1. Deploy the fleet code BEFORE the reboot. PCR15 is extended once per boot
#      with a hash of the code on disk, and a PCR cannot be re-set without
#      rebooting. Seal a key against a PCR15 that describes older code and it
#      works right up until the next reboot, then never again.
#
#   2. Shred the inherited key material BEFORE anything else. The snapshot is a
#      byte copy of a running enclave, so a fresh clone starts life holding that
#      enclave's private key — and, on the source image, world-readable.
#
set -euo pipefail

N="${1:?usage: provision_node.sh <node-number> [--no-seal]}"
NO_SEAL="${2:-}"

# Expanded here, not on the node: the value reaches the remote heredoc already
# substituted, so it never appears in a command line or in shell history there.
if [ -z "${TEE_CALLBACK_SECRET:-}" ]; then
  echo "export TEE_CALLBACK_SECRET first; it must match the middleware's" >&2
  exit 1
fi
CALLBACK_SECRET="$TEE_CALLBACK_SECRET"

RG=TEE-Fleet
VM="kanon-tee-$N"
TEE_ID="tee-$N"
SNAPSHOT=snap-kanon-tee-base
SIZE=Standard_DC2as_v5
SUBNET=snet-tee
VNET=vnet-fleet
REPO_USER=kanonTEE
REPO=/home/kanonTEE/P3DX-SE-manager
VENV=/home/kanonTEE/.env/enclaveManager/bin
MIDDLEWARE_PRIVATE_IP=10.30.0.4
SUB=$(az account show --query id -o tsv)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '\n=== %s ===\n' "$1"; }

say "1/8 OS disk from $SNAPSHOT"
if ! az disk show -g $RG -n "$VM-osdisk" >/dev/null 2>&1; then
  az disk create -g $RG -n "$VM-osdisk" \
    --source "$(az snapshot show -g $RG -n $SNAPSHOT --query id -o tsv)" \
    --security-type ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey \
    --sku StandardSSD_LRS --tags project=spider-fleet -o none
fi

say "2/8 confidential VM $VM"
if ! az vm show -g $RG -n "$VM" >/dev/null 2>&1; then
  az network public-ip create -g $RG -n "pip-$VM" --sku Standard \
    --allocation-method Static -o none
  az vm create -g $RG -n "$VM" \
    --attach-os-disk "$VM-osdisk" --os-type Linux --size $SIZE \
    --security-type ConfidentialVM --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true --enable-secure-boot true \
    --vnet-name $VNET --subnet $SUBNET --public-ip-address "pip-$VM" --nsg "" \
    --assign-identity '[system]' \
    --tags project=spider-fleet role=tee "tee-id=$TEE_ID" -o none
fi
IP=$(az vm show -d -g $RG -n "$VM" --query publicIps -o tsv)
echo "public IP: $IP"

say "3/8 SSH access"
az vm user update -g $RG -n "$VM" -u $REPO_USER \
  --ssh-key-value "$(cat ~/.ssh/id_rsa.pub)" -o none
for _ in $(seq 1 30); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
      "$REPO_USER@$IP" true 2>/dev/null && break
  sleep 10
done

say "4/8 scrub inherited identity and key material"
ssh -o BatchMode=yes "$REPO_USER@$IP" "sudo bash -s" <<'REMOTE'
set -e
systemctl stop enclavemanager.service || true
KEYS=/home/kanonTEE/P3DX-SE-manager/keys
# The clone boots holding the SOURCE enclave's private key. Destroy it before
# the node is reachable for anything else.
for f in private_key.pem public_key.pem private_key.enc kek.pub kek.priv \
         key_generation.json jwt-response.txt deployment_nonce.txt \
         pcr_values.json code_hash.txt image_hash.txt; do
  [ -f "$KEYS/$f" ] && { shred -u "$KEYS/$f" 2>/dev/null || rm -f "$KEYS/$f"; }
done
mkdir -p "$KEYS"; chown -R kanonTEE:kanonTEE "$KEYS"; chmod 700 "$KEYS"
# Clones otherwise share SSH host keys and machine-id with the source.
rm -f /etc/ssh/ssh_host_*; ssh-keygen -A
truncate -s 0 /etc/machine-id; systemd-machine-id-setup
REMOTE
ssh -o BatchMode=yes "$REPO_USER@$IP" "sudo hostnamectl set-hostname $VM"

say "5/8 deploy fleet code (before the reboot — see header)"
TARBALL=$(mktemp /tmp/fleet-XXXX.tgz)
tar czf "$TARBALL" -C "$HERE" \
  Bundle/decryption.py P3DX_SDK.py config.yml deploy_enclave.py \
  enclave/enclave_direct_upload.py enclave_manager_new.py enclavemanager.service \
  lib/config.py lib/direct_upload.py lib/sealed_key.py \
  tools/sealed_key_test.py tools/tpm_seal_check.py
scp -q -o BatchMode=yes "$TARBALL" "$REPO_USER@$IP:/tmp/fleet.tgz"
rm -f "$TARBALL"
ssh -o BatchMode=yes "$REPO_USER@$IP" "sudo bash -s" <<REMOTE
set -e
tar xzf /tmp/fleet.tgz -C $REPO && rm -f /tmp/fleet.tgz
chown -R $REPO_USER:$REPO_USER $REPO
cp $REPO/enclavemanager.service /etc/systemd/system/enclavemanager.service
mkdir -p /etc/systemd/system/enclavemanager.service.d
cat > /etc/systemd/system/enclavemanager.service.d/fleet.conf <<CONF
[Service]
Environment=TEE_ID=$TEE_ID
Environment=KEY_SEALING=on
CONF
chmod 600 /etc/systemd/system/enclavemanager.service.d/fleet.conf
# sudo scrubs the environment, so the deploy subprocess cannot inherit these
# from systemd. A root-owned file keeps the secret off every command line.
mkdir -p /etc/p3dx
cat > /etc/p3dx/callback.conf <<CONF
TEE_CALLBACK_URL=http://$MIDDLEWARE_PRIVATE_IP:4000
TEE_CALLBACK_SECRET=$CALLBACK_SECRET
CONF
chmod 600 /etc/p3dx/callback.conf
systemctl daemon-reload
REMOTE

say "6/8 azure data-plane roles"
MI=$(az vm show -g $RG -n "$VM" --query identity.principalId -o tsv)
for spec in \
  "Storage Blob Data Reader|/subscriptions/$SUB/resourceGroups/TEE/providers/Microsoft.Storage/storageAccounts/anondata2/blobServices/default/containers/encrypted-data" \
  "Storage Blob Data Contributor|/subscriptions/$SUB/resourceGroups/TEE/providers/Microsoft.Storage/storageAccounts/anondata2/blobServices/default/containers/output-data" \
  "Key Vault Secrets User|/subscriptions/$SUB/resourceGroups/Anonymisation/providers/Microsoft.KeyVault/vaults/anon-kv-p3dx"; do
  az role assignment create --assignee-object-id "$MI" --assignee-principal-type ServicePrincipal \
    --role "${spec%%|*}" --scope "${spec##*|}" -o none 2>/dev/null || true
done

say "7/8 reboot so PCR15 measures the code just deployed"
az vm restart -g $RG -n "$VM" -o none
for _ in $(seq 1 30); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$REPO_USER@$IP" true 2>/dev/null && break
  sleep 10
done
sleep 10

if [ "$NO_SEAL" = "--no-seal" ]; then
  say "done (unsealed)"
  echo "Set TEE_CALLBACK_SECRET in /etc/p3dx/callback.conf, then attest:"
  echo "  ssh $REPO_USER@$IP 'curl -s -m 300 http://127.0.0.1:4000/enclave/jwt/fresh'"
  exit 0
fi

say "8/8 attest and seal"
ssh -o BatchMode=yes "$REPO_USER@$IP" \
  "curl -s -m 300 http://127.0.0.1:4000/enclave/jwt/fresh -o /dev/null -w 'attest: http %{http_code}\n'"
ssh -o BatchMode=yes "$REPO_USER@$IP" \
  "curl -s http://127.0.0.1:4000/enclave/identity | ${VENV}/python -c \
   'import json,sys; d=json.load(sys.stdin); print(\"tee_id:\", d[\"tee_id\"], \"sealed:\", d[\"sealed\"], \"fp:\", d[\"key_fingerprint\"][:16])'"

cat <<DONE

$VM is ready.
  private IP : $(az vm show -d -g $RG -n "$VM" --query privateIps -o tsv)
  public IP  : $IP

Remaining, on the middleware:
  1. set TEE_CALLBACK_SECRET in $VM:/etc/p3dx/callback.conf
  2. add to fleet.json:
       {"tee_id": "$TEE_ID",
        "base_url": "http://$(az vm show -d -g $RG -n "$VM" --query privateIps -o tsv):4000",
        "azure_vm_id": "$(az vm show -g $RG -n "$VM" --query id -o tsv)"}
  3. systemctl restart buffermiddleware
DONE
