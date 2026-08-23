# FAKE / EXAMPLE Terraform — do not apply against real infrastructure

resource "azurerm_storage_container" "prod_backups" {
  name                  = "prod-backups-open"
  storage_account_name  = "fakeprodstorage"
  container_access_type = "private"
}

resource "azurerm_storage_container" "internal_logs" {
  name                  = "internal-logs-secure"
  storage_account_name  = "fakeprodstorage"
  container_access_type = "private"
}

resource "azurerm_storage_container" "ghost_container" {
  name                  = "terraform-only-never-created"
  storage_account_name  = "fakeprodstorage"
  container_access_type = "private"
}
