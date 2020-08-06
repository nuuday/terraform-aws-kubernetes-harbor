locals {
  chart_name    = "harbor"
  chart_version = var.chart_version
  release_name  = "harbor"
  namespace     = var.namespace
  repository    = "https://helm.goharbor.io"
  bucket_prefix   = "harbor"
  service_account = "harbor"
  bucket_name    = module.s3_bucket.this_s3_bucket_id
  role_name      = local.bucket_name
  provider_url  = replace(var.oidc_provider_issuer_url, "https://", "")

  values = {
    logLevel = "debug"
    externalURL = "https://${var.ingress_core_hostname}"
    expose = {
      type = "ingress"
      tls = {
        enabled = true
        secretName = "harbor-ingress-tls"
        notarySecretName = "harbor-notary-ingress-tls"
      }
      ingress = {
        controller = var.ingress_class
        annotations = {
          "cert-manager.io/cluster-issuer" : var.ingress_cluster_issuer
        }
        hosts = {
          notary = var.ingress_notary_hostname
          core  = var.ingress_core_hostname
        }
      }
    }
    persistence = {
      enabled = true
      imageChartStorage = {
        type = "s3"
        disableredirect = true
        s3 = {
          region = data.aws_region.harbor.name
          bucket = module.s3_bucket.this_s3_bucket_id

          # Since docker registry is stupid we need to add region endpoint and credentials.
          regionendpoint = "https://s3.${data.aws_region.harbor.name}.amazonaws.com"
          accesskey = aws_iam_access_key.harbor.id
          secretkey = aws_iam_access_key.harbor.secret
        }
      }
    }
    database = {
      type = "external"
      external = {
        username = module.db.this_db_instance_username
        password = module.db.this_db_instance_password
        host = module.db.this_db_instance_address
      }
    }
    chartmuseum = {
      serviceAccountName = local.service_account
    }
    registry = {
      serviceAccountName = local.service_account
    }
    core = {
      serviceAccountName = local.service_account
    }
  }
  db_create_command = <<EOF
    psql -tc "SELECT 1 FROM pg_database WHERE datname = 'registry'" | grep -q 1 || psql -c 'CREATE DATABASE registry'
    psql -tc "SELECT 1 FROM pg_database WHERE datname = 'clair'" | grep -q 1 || psql -c 'CREATE DATABASE clair'
    psql -tc "SELECT 1 FROM pg_database WHERE datname = 'notary_server'" | grep -q 1 || psql -c 'CREATE DATABASE notary_server'
    psql -tc "SELECT 1 FROM pg_database WHERE datname = 'notary_signer'" | grep -q 1 || psql -c 'CREATE DATABASE notary_signer'
  EOF
}


data aws_region "harbor" {}
data aws_caller_identity "harbor" {}

module "iam" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"

  create_role                   = true
  role_name                     = "${local.release_name}-irsa-${random_id.harbor_rds.dec}"
  provider_url                  = local.provider_url
  oidc_fully_qualified_subjects = ["system:serviceaccount:${local.namespace}:${local.service_account}"]

  tags = var.tags
}


data "aws_iam_policy_document" "harbor" {
  statement {
    actions = ["s3:ListAllMyBuckets"]
    resources = ["arn:aws:s3:::*"]
  }
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:ListBucketMultipartUploads"
    ]
    resources = [module.s3_bucket.this_s3_bucket_arn]
  }
  statement {
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:DeleteObject",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload"
    ]
    resources = ["${module.s3_bucket.this_s3_bucket_arn}/*"]
  }
}

resource "aws_iam_role_policy" "harbor" {
  name = local.bucket_name
  role = module.iam.this_iam_role_name

  policy = data.aws_iam_policy_document.harbor.json
}

resource "aws_iam_user_policy" "harbor" {
  name = local.bucket_name
  # role = module.iam.this_iam_role_name
  user = aws_iam_user.harbor.name
  policy = data.aws_iam_policy_document.harbor.json
}

resource "aws_iam_user" "harbor" {
  name = local.bucket_name
  path = "/"
  tags = var.tags
}

resource "aws_iam_access_key" "harbor" {
  user = aws_iam_user.harbor.name
}


module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  bucket_prefix = local.bucket_prefix
  acl           = "private"
  force_destroy = true
  versioning = {
    enabled = false
  }
  tags = var.tags
}

resource "random_id" "harbor_rds" {
  keepers = {
    release_name = local.release_name
  }
  byte_length = 10
}

resource "aws_security_group" "harbor_rds" {
  name_prefix = "harbor-rds"
  vpc_id      = var.vpc_id
}

resource "random_password" "harbor_db_password" {
  length  = 16
  special = false
}

module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier                      = "harbor${random_id.harbor_rds.dec}"
  engine                          = "postgres"
  engine_version                  = "12.2"
  instance_class                  = var.database_instance_type
  allocated_storage               = var.database_storage_size
  storage_encrypted               = false
  name                            = "harbor${random_id.harbor_rds.dec}"
  username                        = "harbor"
  password                        = random_password.harbor_db_password.result
  port                            = "5432"
  vpc_security_group_ids          = [aws_security_group.harbor_rds.id]
  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  backup_retention_period         = 0
  tags                            = var.tags
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  subnet_ids                      = var.database_subnets
  family                          = "postgres12"
  major_engine_version            = "12"
  final_snapshot_identifier       = local.release_name
  deletion_protection             = false
}


resource "aws_security_group_rule" "harbor-cluster-rules" {
  from_port                = 0
  protocol                 = "tcp"
  security_group_id        = aws_security_group.harbor_rds.id
  to_port                  = module.db.this_db_instance_port
  type                     = "ingress"
  source_security_group_id = var.source_security_group
}


resource "kubernetes_namespace" "harbor" {
  metadata {
    name = local.namespace
  }
}
resource "kubernetes_secret" "harbor" {
  metadata {
    name      = "${local.release_name}-credentials"
    namespace = kubernetes_namespace.harbor.metadata[0].name
  }
  data = {
    DATABASE_PASSWORD = module.db.this_db_instance_password
    # GF_AUTH_GITHUB_CLIENT_SECRET = var.oauth_github_client_secret
  }
}
resource "kubernetes_service_account" "harbor" {
  metadata {
    annotations = {
      "eks.amazonaws.com/role-arn" = module.iam.this_iam_role_arn
    }
    name = local.service_account
    namespace = kubernetes_namespace.harbor.metadata[0].name
  }
}
resource "kubernetes_job" "harbor_createdb" {
  metadata {
    name      = "harbor-createdb"
    namespace = kubernetes_namespace.harbor.metadata[0].name
  }
  spec {
    template {
      metadata {
        annotations = {
          "sidecar.istio.io/inject" = "false"
        }
      }
      spec {
        container {
          name  = "harbor-createdb"
          image = "postgres:alpine"
          env {
            name  = "PGHOST"
            value = module.db.this_db_instance_address
          }
          env {
            name  = "PGPORT"
            value = module.db.this_db_instance_port
          }
          env {
            name  = "PGDATABASE"
            value = "postgres"
          }
          env {
            name  = "PGUSER"
            value = module.db.this_db_instance_username
          }
          env {
            name = "PGPASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.harbor.metadata[0].name
                key  = "DATABASE_PASSWORD"
              }
            }
          }
          command = ["/bin/sh", "-c", local.db_create_command]
        }
      }
    }
  }
}

resource "helm_release" "harbor-deploy" {
  name             = local.release_name
  chart            = local.chart_name
  version          = local.chart_version
  repository       = local.repository
  namespace        = kubernetes_job.harbor_createdb.metadata[0].namespace
  create_namespace = true

  wait   = true
  values = [yamlencode(local.values)]

}