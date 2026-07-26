"""AWS Config rule: flag resources whose KMS key has not been rotated recently.

Stock rule cmk-backing-key-rotation-enabled checks whether automatic rotation is
on. Keys with EXTERNAL origin cannot use automatic rotation, so that rule reports
every one of them as non-compliant regardless of how they are actually managed.

This rule resolves the key a resource is encrypted with and checks the date of
its most recent rotation instead.
"""

import datetime
import json
import os

import boto3

MAX_AGE_DAYS = int(os.environ.get("MAX_KEY_AGE_DAYS", "365"))

config = boto3.client("config")
kms = boto3.client("kms")


def key_arn_for(resource_type, resource_id):
    if resource_type == "AWS::RDS::DBInstance":
        rds = boto3.client("rds")
        found = rds.describe_db_instances(DBInstanceIdentifier=resource_id)["DBInstances"][0]
        return found.get("KmsKeyId") if found.get("StorageEncrypted") else None

    if resource_type == "AWS::DynamoDB::Table":
        ddb = boto3.client("dynamodb")
        sse = ddb.describe_table(TableName=resource_id)["Table"].get("SSEDescription", {})
        return sse.get("KMSMasterKeyArn")

    if resource_type == "AWS::S3::Bucket":
        s3 = boto3.client("s3")
        try:
            rules = s3.get_bucket_encryption(Bucket=resource_id)["ServerSideEncryptionConfiguration"]
        except s3.exceptions.ClientError:
            return None
        for rule in rules.get("Rules", []):
            default = rule.get("ApplyServerSideEncryptionByDefault", {})
            if default.get("SSEAlgorithm") == "aws:kms":
                return default.get("KMSMasterKeyID")
        return None

    return None


def rotation_age_days(key_arn):
    """Days since the current key material became current, or None if never rotated."""
    rotations = kms.list_key_rotations(KeyId=key_arn).get("Rotations", [])
    if not rotations:
        return None
    latest = max(r["RotationDate"] for r in rotations)
    return (datetime.datetime.now(datetime.timezone.utc) - latest).days


def evaluate(resource_type, resource_id):
    key_arn = key_arn_for(resource_type, resource_id)
    if key_arn is None:
        return "NON_COMPLIANT", "Resource is not encrypted with a customer managed KMS key"

    meta = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    if meta["KeyManager"] != "CUSTOMER":
        return "NON_COMPLIANT", "Encrypted with an AWS managed key, not a customer managed key"

    age = rotation_age_days(key_arn)
    if age is None:
        return "NON_COMPLIANT", f"Key {meta['KeyId']} has never been rotated"
    if age > MAX_AGE_DAYS:
        return "NON_COMPLIANT", f"Key {meta['KeyId']} last rotated {age} days ago, limit is {MAX_AGE_DAYS}"
    return "COMPLIANT", f"Key {meta['KeyId']} rotated {age} days ago"


def lambda_handler(event, context):
    invoking = json.loads(event["invokingEvent"])
    item = invoking["configurationItem"]
    resource_type = item["resourceType"]
    resource_id = item.get("resourceName") or item["resourceId"]

    if item["configurationItemStatus"] in ("ResourceDeleted", "ResourceNotRecorded"):
        compliance, annotation = "NOT_APPLICABLE", "Resource no longer recorded"
    else:
        try:
            compliance, annotation = evaluate(resource_type, resource_id)
        except Exception as exc:
            compliance, annotation = "NON_COMPLIANT", f"Evaluation failed: {exc}"

    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": item["resourceId"],
                "ComplianceType": compliance,
                "Annotation": annotation[:256],
                "OrderingTimestamp": item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )
    return {"compliance": compliance, "annotation": annotation}
