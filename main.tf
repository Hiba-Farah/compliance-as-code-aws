
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "eu-west-3"
  profile = "personal"
}

resource "aws_s3_bucket" "compliance" {
  bucket_prefix = "compliance-demo-"
}

resource "aws_s3_bucket_public_access_block" "compliance" {
  bucket = aws_s3_bucket.compliance.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliance" {
  bucket = aws_s3_bucket.compliance.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "compliance" {
  bucket = aws_s3_bucket.compliance.id

  versioning_configuration {
    status = "Enabled"
  }
}