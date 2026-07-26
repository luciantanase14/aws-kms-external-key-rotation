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
from botocore.exceptions import ClientError

MAX_AGE_DAYS = int(os.environ.get("MAX_KEY_AGE_DAYS", "365"))
SCOPED_TYPES = ("AWS::RDS::DBInstance", "AWS::DynamoDB::Table", "AWS::S3::Bucket")

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
        except ClientError:
            return None
        for rule in rules.get("Rules", []):
            default = rule.get("ApplyServerSideEncryptionByDefault", {})
            if default.get("SSEAlgorithm") == "aws:kms":
                return default.get("KMSMasterKeyID")
        return None

    return None


def rotation_age_days(key_arn):
    """Days since the current key material became current, or None if never rotated."""
    rotations = []
    paginator = kms.get_paginator("list_key_rotations")
    for page in paginator.paginate(KeyId=key_arn):
        rotations.extend(page.get("Rotations", []))
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


def evaluation_for(resource_type, resource_id, timestamp, physical_id):
    try:
        compliance, annotation = evaluate(resource_type, resource_id)
    except Exception as exc:
        compliance, annotation = "NON_COMPLIANT", f"Evaluation failed: {exc}"
    return {
        "ComplianceResourceType": resource_type,
        "ComplianceResourceId": physical_id,
        "ComplianceType": compliance,
        "Annotation": annotation[:256],
        "OrderingTimestamp": timestamp,
    }


def from_change_notification(invoking):
    item = invoking["configurationItem"]
    timestamp = item["configurationItemCaptureTime"]
    if item["configurationItemStatus"] in ("ResourceDeleted", "ResourceNotRecorded"):
        return [
            {
                "ComplianceResourceType": item["resourceType"],
                "ComplianceResourceId": item["resourceId"],
                "ComplianceType": "NOT_APPLICABLE",
                "Annotation": "Resource no longer recorded",
                "OrderingTimestamp": timestamp,
            }
        ]
    return [
        evaluation_for(
            item["resourceType"],
            item.get("resourceName") or item["resourceId"],
            timestamp,
            item["resourceId"],
        )
    ]


def from_scheduled_run(invoking):
    """A scheduled invocation carries no configurationItem, so discover resources."""
    timestamp = invoking["notificationCreationTime"]
    evaluations = []
    paginator = config.get_paginator("list_discovered_resources")
    for resource_type in SCOPED_TYPES:
        for page in paginator.paginate(resourceType=resource_type):
            for found in page["resourceIdentifiers"]:
                evaluations.append(
                    evaluation_for(
                        resource_type,
                        found.get("resourceName") or found["resourceId"],
                        timestamp,
                        found["resourceId"],
                    )
                )
    return evaluations


def lambda_handler(event, context):
    invoking = json.loads(event["invokingEvent"])
    message_type = invoking.get("messageType")

    if message_type == "ScheduledNotification":
        evaluations = from_scheduled_run(invoking)
    else:
        evaluations = from_change_notification(invoking)

    # put_evaluations accepts at most 100 per call.
    for start in range(0, len(evaluations), 100):
        config.put_evaluations(
            Evaluations=evaluations[start : start + 100],
            ResultToken=event["resultToken"],
        )
    return {"evaluated": len(evaluations)}
