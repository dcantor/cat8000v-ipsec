# Cisco Network-as-Code for the C8000v IPsec VTI + eBGP lab (hub, spoke1, spoke2).
# Module 0.1.0 / provider 0.15.0 over RESTCONF (see README). Credentials from the
# environment: ../lab.sh nac sets IOSXE_USERNAME / IOSXE_PASSWORD (admin/admin).
module "iosxe" {
  source  = "netascode/nac-iosxe/iosxe"
  version = "0.1.0"

  yaml_directories = ["data"]
  save_config      = false          # lab.sh nac apply saves via the cisco-ia:save-config RPC
  write_model_file = "rendered-model.yaml"
}
