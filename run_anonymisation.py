#!/usr/bin/env python3
"""Minimal in-TEE anonymisation run.

The trimmed-down counterpart to deploy_enclave.py. Where that flow performs the
full 11-step attestation handshake (vTPM measurement -> MAA JWT -> JWT to UI ->
wait for an RSA-wrapped key bundle -> decrypt it), this one does only what the
anonymisation demo needs:

    fetch encrypted dataset -> fetch key from Key Vault -> decrypt -> run SKALD

The dataset key is pulled straight from Key Vault by the CVM's managed identity
over IMDS, so nothing has to be handed to the guest out-of-band and no bundle is
involved. The application (SKALD) and its config are fixed and already present
in the image.

Consequence worth being explicit about: this path does NOT demonstrate the TEE's
trust properties. No attestation report is produced and no image measurement is
checked, so the SKALD image is trusted on the strength of the registry alone.
deploy_enclave.py remains the flow that proves attestation.

Output is left in /tmp/tee_output for GET /enclave/output to serve; it is not
encrypted and uploaded to blob storage on this path.
"""

import argparse
import sys
import traceback

import P3DX_SDK
from lib.config import config

# Force unbuffered output for live logging (journalctl -t tee-anon -f)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

MAX_STEPS = 6


def box_out(message):
    """Prints a box around a message using text characters."""
    lines = message.splitlines()
    max_width = max(len(line) for line in lines) if lines else 0

    print("+" + "-" * (max_width + 2) + "+", flush=True)
    for line in lines:
        print("| " + line.ljust(max_width) + " |", flush=True)
    print("+" + "-" * (max_width + 2) + "+", flush=True)


def manager_address():
    """Resolve the local enclave-manager address for setState callbacks.

    deploy_enclave.py reads this from DPconfig.json, which is provisioned on the
    VM rather than committed. Fall back to the configured service host/port so a
    missing DPconfig.json doesn't fail the run — the address only targets this
    machine's own manager.
    """
    try:
        dp_config = P3DX_SDK.load_config_file(config.get_path('config_file'))
        address = dp_config.get("enclaveManagerAddress")
        if address:
            return address
    except (FileNotFoundError, ValueError) as exc:
        print(f"Note: falling back to configured service address ({exc})", flush=True)

    return f"http://0.0.0.0:{config.service.port}"


def set_state(title, step, address):
    """Best-effort state update — a failed callback must not kill the run."""
    try:
        P3DX_SDK.setState(title, f"Step {step}", step, MAX_STEPS, address)
    except Exception as exc:
        print(f"Warning: setState failed at step {step}: {exc}", flush=True)


def parse_args():
    """Parse the run parameters the orchestrator passes in.

    The dataset location comes from the contract (datasetDetails.resourceUrl),
    relayed by the governance layer — it is NOT baked into the image. Only the
    Key Vault URL stays fixed, since the key custody arrangement is a property
    of the deployment rather than of any one contract. config.demo values remain
    as fallbacks so the script is still runnable by hand for debugging.
    """
    p = argparse.ArgumentParser(description="Run the in-TEE anonymisation.")
    p.add_argument("--dataset-url", default=None,
                   help="encrypted dataset blob URL (from the contract)")
    p.add_argument("--keyvault-url", default=None,
                   help="Key Vault secret URL holding the dataset key")
    p.add_argument("--contract-id", default="", help="for log correlation")
    p.add_argument("--tee-id", default="", help="for log correlation")
    return p.parse_args()


def main():
    """Minimal anonymisation workflow."""
    args = parse_args()
    address = manager_address()

    dataset_url = args.dataset_url or config.demo.dataset_blob_url
    keyvault_url = args.keyvault_url or config.demo.kms_secret_url

    if not dataset_url:
        raise ValueError(
            "No dataset URL: pass --dataset-url (relayed from the contract's "
            "datasetDetails.resourceUrl) or set demo.dataset_blob_url in config.yml"
        )

    print("=" * 60, flush=True)
    print("TEE Anonymisation Run (minimal path)", flush=True)
    print("=" * 60, flush=True)
    print(f"contract_id : {args.contract_id or '(none)'}", flush=True)
    print(f"tee_id      : {args.tee_id or '(none)'}", flush=True)
    print(f"dataset     : {dataset_url}"
          f"{'' if args.dataset_url else '   [fallback: config.demo]'}", flush=True)
    print(f"key vault   : {keyvault_url}", flush=True)

    # Step 1 - Clean and prepare the three SKALD mount points
    print("\n" + "=" * 60, flush=True)
    print("Step 1: Preparing TEE folders", flush=True)
    print("=" * 60, flush=True)
    box_out("Preparing TEE input/output folders...")
    set_state("Preparing TEE folders", 1, address)
    P3DX_SDK.ensure_tee_folders()

    # Step 2 - Stage the fixed anonymisation config
    print("\n" + "=" * 60, flush=True)
    print("Step 2: Staging SKALD config", flush=True)
    print("=" * 60, flush=True)
    box_out("Staging fixed SKALD anonymisation config...")
    set_state("Staging anonymisation config", 2, address)
    config_path = P3DX_SDK.stage_skald_config()
    print(f"Config staged at {config_path}", flush=True)

    # Step 3 - Fetch the encrypted dataset and decrypt it with the Key Vault key
    print("\n" + "=" * 60, flush=True)
    print("Step 3: Fetching and Decrypting Data", flush=True)
    print("=" * 60, flush=True)
    box_out("Fetching encrypted data and key (managed identity)...")
    set_state("Fetching and decrypting data", 3, address)
    dataset_path = P3DX_SDK.fetch_and_decrypt_minimal(dataset_url, keyvault_url)
    print(f"Dataset ready at {dataset_path}", flush=True)

    # Step 4 - Pull the application
    print("\n" + "=" * 60, flush=True)
    print("Step 4: Pulling Application Image", flush=True)
    print("=" * 60, flush=True)
    box_out("Pulling docker compose and SKALD image...")
    set_state("Pulling application image", 4, address)
    P3DX_SDK.pull_compose_file(config.demo.compose_url)
    link = P3DX_SDK.extract_docker_image_from_compose()
    print(f"Docker image: {link}", flush=True)
    P3DX_SDK.pull_docker_image(link)
    print("Docker image pulled", flush=True)

    # Step 5 - Run SKALD over the decrypted data
    print("\n" + "=" * 60, flush=True)
    print("Step 5: Running Anonymisation", flush=True)
    print("=" * 60, flush=True)
    box_out("Running SKALD in Docker...")
    set_state("Running anonymisation in TEE", 5, address)
    P3DX_SDK.run_docker_containers()

    # Step 6 - Done; output stays in /tmp/tee_output for GET /enclave/output
    print("\n" + "=" * 60, flush=True)
    print("ANONYMISATION COMPLETE", flush=True)
    print("=" * 60, flush=True)
    print(f"Output available in {config.paths.tee_output}", flush=True)
    print("Retrieve via GET /enclave/output", flush=True)
    set_state("Anonymisation complete", 6, address)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nRun interrupted by user", flush=True)
        exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}", flush=True)
        traceback.print_exc()
        exit(1)
