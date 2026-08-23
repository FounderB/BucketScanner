resource "yandex_storage_bucket" "declared" {
  bucket = "declared-in-tf"
  acl    = "private"
}
