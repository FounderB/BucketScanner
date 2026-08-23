# FAKE / EXAMPLE Terraform — do not apply against real infrastructure

resource "google_storage_bucket" "prod_backups" {
  name                     = "prod-backups-open"
  public_access_prevention = "enforced"

  uniform_bucket_level_access {
    enabled = true
  }
}

resource "google_storage_bucket" "internal_logs" {
  name                     = "internal-logs-secure"
  public_access_prevention = "enforced"

  uniform_bucket_level_access {
    enabled = true
  }
}

resource "google_storage_bucket" "ghost_bucket" {
  name                     = "terraform-only-never-created"
  public_access_prevention = "enforced"

  uniform_bucket_level_access {
    enabled = true
  }
}
