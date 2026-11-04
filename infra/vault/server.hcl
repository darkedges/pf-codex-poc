ui = false
disable_mlock = false
api_addr = "https://localhost:9470"
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/cert.pem"
  tls_key_file = "/vault/tls/key.pem"
  tls_min_version = "tls12"
}
