variable "auth_url" {
  type = string
}

variable "user_name" {
  type = string
}

variable "password" {
  type      = string
  sensitive = true
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "RegionOne"
}

variable "image_name" {
  type = string
}

variable "flavor_name" {
  type = string
}
