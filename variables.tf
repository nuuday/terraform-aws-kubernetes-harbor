variable "chart_version" {
  default     = "1.4.1"
  description = "harbor version to install"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "database_instance_type" {
  default     = "db.t3.micro"
  description = "RDS Database instance type"
  type        = string
}

variable "namespace" {
  default     = "harbor"
  description = "Kubernetes namespace to deploy to"
  type        = string
}

variable "oidc_provider_issuer_url" {
  description = "Issuer used in the OIDC provider associated with the EKS cluster to support IRSA."
  type        = string
}


variable "database_subnets" {
  description = "AWS database subnets"
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to taggable resources provisioned by this module."
  type        = map(string)
  default     = {}
}

variable "source_security_group" {
  type        = string
  description = "Source security groups RDS should accept connections from"
}

variable "database_storage_size" {
  description = "Disk space to allocation for RDS instance"
  default     = 5
  type        = number
}

variable "ingress_notary_hostname" {
  default = ""
}
variable "ingress_core_hostname" {
  default = ""
}


variable "ingress_enabled" {
  type = bool
  default = false
  description = "Enable or disable creation of ingress resources"
}

variable "ingress_cluster_issuer" {
  type = string
  default = "letsencrypt"
  description = "Cert-manager cluster issuer"
}

variable "ingress_class" {
  type = string
  default = "nginx"
  description = "Ingress class"
}
