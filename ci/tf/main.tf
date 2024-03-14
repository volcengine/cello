# https://registry.terraform.io/providers/volcengine/volcengine/latest/docs
terraform {
  required_providers {
    volcengine = {
      source = "volcengine/volcengine"
      version = "0.0.73"
    }
  }
}

variable "access_key" {
  type = string
}

variable "secret_key" {
  type = string
}

variable "key_pair_name" {
  type = string
}

variable "key_pair_path" {
  type = string
}

variable "region" {
  type = string
}

variable "zone_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "vpc_name" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "node_subnet_name" {
  type = string
}

variable "node_subnet_cidr" {
  type = string
}

variable "pod_subnet_name" {
  type = string
}

variable "pod_subnet_cidr" {
  type = string
}

variable "control_plane_node_name" {
  type = string
}

variable "worker_node_name" {
  type = string
}

variable "worker2_node_name" {
  type = string
}

variable "control_eip_name" {
  type = string
}


variable "project_name" {
  type = string
}

# Configure the Volcengine Provider
provider "volcengine" {
  access_key = var.access_key
  secret_key = var.secret_key
  region = var.region
}

resource "volcengine_vpc" "vpc_cello" {
  vpc_name   = var.vpc_name
  cidr_block = var.vpc_cidr
  project_name = var.project_name
  enable_ipv6 = true
}

resource "volcengine_subnet" "subnet_node" {
  subnet_name = var.node_subnet_name
  cidr_block  = var.node_subnet_cidr
  enable_ipv6 = true
  ipv6_cidr_block = 1
  zone_id     = var.zone_id
  vpc_id      = volcengine_vpc.vpc_cello.id
}


resource "volcengine_subnet" "subnet_pod" {
  subnet_name = var.pod_subnet_name
  cidr_block  = var.pod_subnet_cidr
  enable_ipv6 = true
  ipv6_cidr_block = 2
  zone_id     = var.zone_id
  vpc_id      = volcengine_vpc.vpc_cello.id
}

data "volcengine_security_groups" "sg_default" {
  name_regex = "Default"
  vpc_id = volcengine_vpc.vpc_cello.id
}

resource "volcengine_security_group_rule" "sg_rule_allow_api_server" {
  direction         = "ingress"
  security_group_id = data.volcengine_security_groups.sg_default.security_groups[0].id
  protocol          = "tcp"
  port_start        = "6443"
  port_end          = "6443"
  cidr_ip           = "0.0.0.0/0"
}

resource "volcengine_ecs_instance" "control_plane" {
  zone_id              = var.zone_id
  image_id             = "image-ybqi99s7yq8rx7mnk44b"
  instance_type        = var.instance_type
  instance_name        = var.control_plane_node_name
  description          = var.control_plane_node_name
  host_name            = var.control_plane_node_name
  key_pair_name        = var.key_pair_name
  instance_charge_type = "PostPaid"
  system_volume_type   = "ESSD_FlexPL"
  system_volume_size   = 40
  subnet_id            = volcengine_subnet.subnet_node.id
  ipv6_address_count   = 1
  security_group_ids   = [data.volcengine_security_groups.sg_default.security_groups[0].id]
  project_name = var.project_name
}

resource "volcengine_ecs_instance" "worker" {
  zone_id              = var.zone_id
  image_id             = "image-ybqi99s7yq8rx7mnk44b"
  instance_type        = var.instance_type
  instance_name        = var.worker_node_name
  description          = var.worker_node_name
  host_name            = var.worker_node_name
  key_pair_name        = var.key_pair_name
  instance_charge_type = "PostPaid"
  system_volume_type   = "ESSD_FlexPL"
  system_volume_size   = 40
  subnet_id            = volcengine_subnet.subnet_node.id
  ipv6_address_count   = 1
  security_group_ids   = [data.volcengine_security_groups.sg_default.security_groups[0].id]
  project_name = var.project_name
}

resource "volcengine_ecs_instance" "worker2" {
  zone_id              = var.zone_id
  image_id             = "image-ybqi99s7yq8rx7mnk44b"
  instance_type        = var.instance_type
  instance_name        = var.worker2_node_name
  description          = var.worker2_node_name
  host_name            = var.worker2_node_name
  key_pair_name        = var.key_pair_name
  instance_charge_type = "PostPaid"
  system_volume_type   = "ESSD_FlexPL"
  system_volume_size   = 40
  subnet_id            = volcengine_subnet.subnet_node.id
  ipv6_address_count   = 1
  security_group_ids   = [data.volcengine_security_groups.sg_default.security_groups[0].id]
  project_name = var.project_name
}

resource "volcengine_eip_address" "control_plane" {
  billing_type = "PostPaidByBandwidth"
  bandwidth    = 10
  name         = var.control_eip_name
  description  = "EIP for control-plane node"
  project_name = var.project_name
}

resource "volcengine_eip_associate" "foo" {
  allocation_id = resource.volcengine_eip_address.control_plane.id
  instance_id   = resource.volcengine_ecs_instance.control_plane.id
  instance_type = "EcsInstance"
}

resource "local_file" "hosts" {
  content  = templatefile(
    "${path.module}/hosts.tftpl",
    {
      control_plane_nodes = [resource.volcengine_ecs_instance.control_plane.primary_ip_address],
      worker_nodes = [resource.volcengine_ecs_instance.worker.primary_ip_address, resource.volcengine_ecs_instance.worker2.primary_ip_address]
      jump_host = resource.volcengine_eip_address.control_plane.eip_address
      key_pair_path = var.key_pair_path
    }
  )
  filename = "hosts.yaml"
}

resource "local_file" "values" {
  content  = templatefile(
    "${path.module}/values.tftpl",
    {
      pod_subnet_id = volcengine_subnet.subnet_pod.id
      pod_sg_id = data.volcengine_security_groups.sg_default.security_groups[0].id
      k8s_api_server_ip = resource.volcengine_ecs_instance.control_plane.primary_ip_address
      access_key = var.access_key
      secret_key = var.secret_key
    }
  )
  filename = "values.yaml"
}
