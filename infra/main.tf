# ThreatOps Sentinel — Phase 1 AWS Infrastructure
# Provisions: S3 bucket, Kinesis stream, Lambda, GuardDuty, CloudTrail

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "threatops-sentinel-tfstate"
    key    = "phase1/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ────────────────────────────────────────────────────────────────
variable "aws_region"    { default = "us-east-1" }
variable "project"       { default = "threatops-sentinel" }
variable "environment"   { default = "prod" }

locals {
  tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ── S3 Bucket: Normalized Events ─────────────────────────────────────────────
resource "aws_s3_bucket" "events" {
  bucket = "${var.project}-events-${var.environment}"
  tags   = local.tags
}

resource "aws_s3_bucket_versioning" "events" {
  bucket = aws_s3_bucket.events.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "events" {
  bucket = aws_s3_bucket.events.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "events" {
  bucket                  = aws_s3_bucket.events.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Kinesis Data Stream ───────────────────────────────────────────────────────
resource "aws_kinesis_stream" "events" {
  name             = "${var.project}-stream"
  shard_count      = 1
  retention_period = 24
  tags             = local.tags
}

# ── IAM Role: Lambda Execution ────────────────────────────────────────────────
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project}-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project}-lambda-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = ["${aws_s3_bucket.events.arn}", "${aws_s3_bucket.events.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream", "kinesis:ListShards"]
        Resource = aws_kinesis_stream.events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["guardduty:ListFindings", "guardduty:GetFindings", "guardduty:ListDetectors"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# ── GuardDuty Detector ────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs { enable = true }
    kubernetes { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings { ebs_volumes { enable = true } }
    }
  }
  tags = local.tags
}

# ── CloudTrail ────────────────────────────────────────────────────────────────
resource "aws_cloudtrail" "main" {
  name                          = "${var.project}-trail"
  s3_bucket_name                = aws_s3_bucket.events.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  tags                          = local.tags
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "events_bucket_name" { value = aws_s3_bucket.events.bucket }
output "kinesis_stream_arn"  { value = aws_kinesis_stream.events.arn }
output "guardduty_detector"  { value = aws_guardduty_detector.main.id }
