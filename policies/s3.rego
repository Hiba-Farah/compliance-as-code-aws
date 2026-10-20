
package main

import rego.v1

deny contains msg if {
    resource := input.resource.aws_s3_bucket[_]
    resource.acl == "public-read"
    msg := "Interdit : un bucket S3 ne doit pas avoir une ACL public-read."
}

deny contains msg if {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    resource.block_public_acls == false
    msg := "Interdit : le blocage des ACL publiques S3 doit être activé."
}

deny contains msg if {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    resource.block_public_policy == false
    msg := "Interdit : le blocage des politiques publiques S3 doit être activé."
}
