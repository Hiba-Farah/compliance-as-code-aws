package main

import rego.v1

# Interdire les ACL publiques
deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket
    resource.acl == "public-read"
    msg := sprintf("Interdit : le bucket S3 '%s' utilise une ACL public-read.", [name])
}

deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket
    resource.acl == "public-read-write"
    msg := sprintf("Interdit : le bucket S3 '%s' utilise une ACL public-read-write.", [name])
}

# Exiger le blocage des ACL et politiques publiques
deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_public_access_block
    resource.block_public_acls == false
    msg := sprintf("Interdit : block_public_acls doit être activé pour '%s'.", [name])
}

deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_public_access_block
    resource.block_public_policy == false
    msg := sprintf("Interdit : block_public_policy doit être activé pour '%s'.", [name])
}

deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_public_access_block
    resource.ignore_public_acls == false
    msg := sprintf("Interdit : ignore_public_acls doit être activé pour '%s'.", [name])
}

deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_public_access_block
    resource.restrict_public_buckets == false
    msg := sprintf("Interdit : restrict_public_buckets doit être activé pour '%s'.", [name])
}

# Exiger le chiffrement AES-256 ou AWS KMS
deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_server_side_encryption_configuration
    rule := resource.rule[_]
    algorithm := rule.apply_server_side_encryption_by_default.sse_algorithm
    not algorithm in {"AES256", "aws:kms", "aws:kms:dsse"}
    msg := sprintf("Interdit : algorithme de chiffrement non conforme pour '%s'.", [name])
}

# Exiger le versioning activé
deny contains msg if {
    some name, resource in input.resource.aws_s3_bucket_versioning
    versioning := resource.versioning_configuration[_]
    versioning.status != "Enabled"
    msg := sprintf("Interdit : le versioning doit être activé pour '%s'.", [name])
}
