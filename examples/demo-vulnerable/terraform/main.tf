# FAKE / EXAMPLE Terraform — do not apply against real infrastructure

resource "yandex_storage_bucket" "prod_backups" {
  bucket = "prod-backups-open"
  acl    = "private"
}

resource "yandex_storage_bucket" "internal_logs" {
  bucket = "internal-logs-secure"
  acl    = "private"
}

resource "yandex_storage_bucket" "ghost_bucket" {
  bucket = "terraform-only-never-created"
  acl    = "private"
}
