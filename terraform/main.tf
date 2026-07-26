terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
    }
  }
}

variable "max_key_age_days" {
  description = "Days since the last rotation before a resource is reported non-compliant."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/../config-rule/handler.py"
  output_path = "${path.module}/handler.zip"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rule" {
  name               = "kms-rotation-drift"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "rule" {
  statement {
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:ListKeyRotations",
      "rds:DescribeDBInstances",
      "dynamodb:DescribeTable",
      "s3:GetEncryptionConfiguration",
      "config:PutEvaluations",
      "config:ListDiscoveredResources",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "rule" {
  name   = "kms-rotation-drift"
  role   = aws_iam_role.rule.id
  policy = data.aws_iam_policy_document.rule.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.rule.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "rule" {
  function_name    = "kms-rotation-drift"
  role             = aws_iam_role.rule.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  tags             = var.tags

  environment {
    variables = {
      MAX_KEY_AGE_DAYS = var.max_key_age_days
    }
  }
}

resource "aws_lambda_permission" "config" {
  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rule.function_name
  principal     = "config.amazonaws.com"
}

resource "aws_config_config_rule" "rotation" {
  name = "kms-key-rotation-age"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.rule.arn

    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }

    source_detail {
      event_source                = "aws.config"
      message_type                = "ScheduledNotification"
      maximum_execution_frequency = "TwentyFour_Hours"
    }
  }

  scope {
    compliance_resource_types = [
      "AWS::RDS::DBInstance",
      "AWS::DynamoDB::Table",
      "AWS::S3::Bucket",
    ]
  }

  depends_on = [aws_lambda_permission.config]
  tags       = var.tags
}

output "config_rule_name" {
  description = "Config rule reporting rotation drift."
  value       = aws_config_config_rule.rotation.name
}

output "lambda_arn" {
  description = "Evaluation function backing the rule."
  value       = aws_lambda_function.rule.arn
}
