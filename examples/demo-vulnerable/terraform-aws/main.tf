# FAKE / EXAMPLE Terraform — do not apply against real infrastructure

resource "aws_s3_bucket" "prod_backups" {
  bucket = "prod-backups-open"
}

resource "aws_s3_bucket_acl" "prod_backups" {
  bucket = aws_s3_bucket.prod_backups.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "prod_backups" {
  bucket                  = aws_s3_bucket.prod_backups.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "internal_logs" {
  bucket = "internal-logs-secure"
}

resource "aws_s3_bucket_acl" "internal_logs" {
  bucket = aws_s3_bucket.internal_logs.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "internal_logs" {
  bucket                  = aws_s3_bucket.internal_logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "ghost_bucket" {
  bucket = "terraform-only-never-created"
}
