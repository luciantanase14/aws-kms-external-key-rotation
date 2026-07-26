#!/usr/bin/env python3
"""Rotate the key material of a KMS key with EXTERNAL origin.

The key ID and ARN do not change, so nothing that references the key needs to be
re-encrypted or migrated. Previous key material stays available for decrypt.

    rotate.py --key-id <id> --wrapped-material wrapped.bin --import-token token.bin
    rotate.py --key-id <id> --status

Wrapping happens in the HSM. This tool never sees plaintext key material: it
fetches the wrapping parameters, hands them to the HSM operator, and imports the
blob the HSM produces.
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

WRAPPING_ALGORITHM = "RSA_AES_KEY_WRAP_SHA_256"
WRAPPING_SPEC = "RSA_4096"
MAX_ON_DEMAND_ROTATIONS = 25


def get_import_parameters(kms, key_id, outdir):
    resp = kms.get_parameters_for_import(
        KeyId=key_id,
        WrappingAlgorithm=WRAPPING_ALGORITHM,
        WrappingKeySpec=WRAPPING_SPEC,
    )
    pub = f"{outdir}/wrapping_public_key.bin"
    token = f"{outdir}/import_token.bin"
    with open(pub, "wb") as fh:
        fh.write(resp["PublicKey"])
    with open(token, "wb") as fh:
        fh.write(resp["ImportToken"])

    print(f"wrapping key   {pub}")
    print(f"import token   {token}")
    print(f"algorithm      {WRAPPING_ALGORITHM} over {WRAPPING_SPEC}")
    print(f"valid until    {resp['ParametersValidTo'].isoformat()}")
    print("\nWrap the key material inside the HSM using the public key above,")
    print("then pass the wrapped blob and this token back to --wrapped-material.")
    return resp


def import_material(kms, key_id, wrapped_path, token_path, expires_days):
    with open(wrapped_path, "rb") as fh:
        wrapped = fh.read()
    with open(token_path, "rb") as fh:
        token = fh.read()

    kwargs = {
        "KeyId": key_id,
        "ImportToken": token,
        "EncryptedKeyMaterial": wrapped,
        "ImportType": "NEW_KEY_MATERIAL",
    }
    if expires_days:
        kwargs["ExpirationModel"] = "KEY_MATERIAL_EXPIRES"
        kwargs["ValidTo"] = datetime.now(timezone.utc) + timedelta(days=expires_days)
    else:
        kwargs["ExpirationModel"] = "KEY_MATERIAL_DOES_NOT_EXPIRE"

    kms.import_key_material(**kwargs)
    print("imported as pending rotation")


def rotate(kms, key_id):
    status = kms.get_key_rotation_status(KeyId=key_id)
    remaining = MAX_ON_DEMAND_ROTATIONS - len(
        kms.list_key_rotations(KeyId=key_id).get("Rotations", [])
    )
    if remaining <= 0:
        sys.exit(
            f"key {key_id} has used all {MAX_ON_DEMAND_ROTATIONS} on-demand rotations. "
            "Further rotation needs a new key and a data migration."
        )
    if status.get("OnDemandRotationStartDate"):
        sys.exit("a rotation is already in progress on this key")

    kms.rotate_key_on_demand(KeyId=key_id)
    print(f"rotation started, {remaining - 1} on-demand rotations left after this one")


def show_status(kms, key_id):
    key = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    if key["Origin"] != "EXTERNAL":
        sys.exit(f"key {key_id} has origin {key['Origin']}, this tool is for EXTERNAL keys")

    rotations = kms.list_key_rotations(KeyId=key_id).get("Rotations", [])
    print(f"key      {key['Arn']}")
    print(f"state    {key['KeyState']}")
    print(f"expires  {key.get('ValidTo', 'never')}")
    print(f"used     {len(rotations)} of {MAX_ON_DEMAND_ROTATIONS} on-demand rotations")
    if rotations:
        print(f"last     {rotations[-1]['RotationDate'].isoformat()}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key-id", required=True)
    ap.add_argument("--region")
    ap.add_argument("--status", action="store_true", help="show rotation state and exit")
    ap.add_argument("--get-parameters", metavar="DIR", help="fetch wrapping key and import token")
    ap.add_argument("--wrapped-material", help="key material wrapped by the HSM")
    ap.add_argument("--import-token", help="token returned with the wrapping key")
    ap.add_argument("--expires-days", type=int, default=0, help="0 means material does not expire")
    ap.add_argument("--rotate", action="store_true", help="promote pending material to current")
    args = ap.parse_args()

    kms = boto3.client("kms", region_name=args.region)

    try:
        if args.status:
            show_status(kms, args.key_id)
        elif args.get_parameters:
            get_import_parameters(kms, args.key_id, args.get_parameters)
        elif args.wrapped_material:
            if not args.import_token:
                sys.exit("--wrapped-material requires --import-token")
            import_material(
                kms, args.key_id, args.wrapped_material, args.import_token, args.expires_days
            )
        elif args.rotate:
            rotate(kms, args.key_id)
        else:
            ap.error("choose one of --status, --get-parameters, --wrapped-material, --rotate")
    except ClientError as exc:
        sys.exit(f"kms error: {exc.response['Error']['Message']}")


if __name__ == "__main__":
    main()
