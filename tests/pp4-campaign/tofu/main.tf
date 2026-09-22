terraform {
  required_version = "= 1.12.6"

  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "= 3.4.0"
    }
  }
}

provider "openstack" {
  auth_url    = var.auth_url
  user_name   = var.user_name
  password    = var.password
  tenant_id   = var.project_id
  region      = var.region
  insecure    = true
  max_retries = 0
}

data "openstack_images_image_v2" "probe" {
  name = var.image_name
}

data "openstack_compute_flavor_v2" "probe" {
  name = var.flavor_name
}

# One representative previously certified managed operation (P13 profile:
# openstack_networking_network_v2 / openstack_networking_subnet_v2).
resource "openstack_networking_network_v2" "pp4" {
  name           = "pp4-tofu-network"
  admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "pp4" {
  name       = "pp4-tofu-subnet"
  network_id = openstack_networking_network_v2.pp4.id
  cidr       = "198.51.100.0/29"
}

output "network_id" {
  value = openstack_networking_network_v2.pp4.id
}

output "image_id" {
  value = data.openstack_images_image_v2.probe.id
}

output "flavor_id" {
  value = data.openstack_compute_flavor_v2.probe.id
}
