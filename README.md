# Migration Evaluator for AWS IAM Identity Center (IDC ME)

## Authors 
* Jonathan VanKim
* Valentine Reid


## Overview

Permissions and assignment of permissions in Identity Center is by definition different than how IAM Federation is designed. Identity Center expects customers to build common permission sets to be applied to many AWS accounts within their organization. Individual federated roles should only be migrated in a 1:1 mapping to permission sets only after all other options have been evaluated and completed. 

* Identify permissions that are applied to all accounts in the organization
* Identify permissions for common but not ubiquitous roles 

The primary outcome of this evaluator is to identify bespoke permissions for individual accounts not covered by other permission sets. IdC ME has been developed to evaluate IAM Federated Roles in an AWS Account and produce artifacts to assist customers migrate an AWS Account to Identity Center. 

## Artifacts

### CSV - Import Data


A CSV file `identity_center_import_123456789012.csv` is generated by the python script to provide customers with the data necessary to build permission sets. This data can be combined with additional customer input to build assignments. 

Role | Policy Name | CMP AMP | Permission Boundary | CMP/AMP | Permission Set Name | Account Number | IdP Group Name
---|---|---|---|---|---|---|---
_federated_role_with_permission_boundary | SecretsManagerABAC | cmp | ConfigAccessPolicy | cmp | _federated_role_with_permis_owC | 123456789012 | Group4



### CSV - SQS Resource Policy Evaluation

A CSV file `resource_policies_to_migrate_123456789012_sqs.csv` is generated by the python script to report the SQS resource policies that contains principals that have been identified as being impacted by migration. The code used to generate this CSV is an example of how customers can develop this script further to evaluate other service resource policies. For a list of all services that have resource policies see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html 

RoleARN | SQSQueueUrl
---|---
arn:aws:iam::123456789012:role/EmergencyAccess_Role2_RO | sqs.Queue(url='https://sqs.us-east-1.amazonaws.com/123456789012/queue-withprincipalarn')

### CloudFormation - Inline Role Creation 

The file `inline_role_policy_cfn.json` is generated by the script and this CloudFormation template can be used to convert inline role policies into customer managed policies within the same account so that when the permission set and assignment is built to replace the migrating role the inline policy permissions aren't lost. 

## Permissions used by IdC - ME

Service | Action | boto3 | Reason
---|---|---|---
iam | list_saml_providers | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_saml_providers | This action allows the script to prompt the user which SAML provider in the account is migrating to Identity Center 
iam | list_roles | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Paginator.ListRoles | This allows the script to evaluate all roles in the account to determine if the AssumeRolePolicyDocument trusts the federated SAML provider that is migrating to Identity Center.
iam | list_attached_role_policies | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_attached_role_policies | This action lists all Customer Managed Polices and Amazon Managed Policies for the roles that are migrating to Identity Center. 
iam | list_role_policies | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_role_policies | This action gets any inline policy names attached to the roles migrating to identity center. 
iam | get_role_policy | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role_policy | This action gets the JSON policy document for attached inline role policies
iam | get_role | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role | This action gets detailed role information for roles that have been identified as migrating to Identity Center. 
ssm | get_parameters_by_path | https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ssm.html#SSM.Client.get_parameters_by_path | This action is required for resource policy evaluation as the script queries an AWS managed parameter that lists all AWS Regions. 

## Known limitations and enhancement opportunities 

This script is being provided as a proof of concept (PoC) of how customers can programmatically evaluate an AWS Organization to migrate from IAM federation to Identity Center. As it is a PoC there are known limitations that customers evaluating this script should be aware of. 

* [ ] - Only identifies single federated SAML provider in role trust policy. Does not include exception handling for role trust policies that contain multiple SAML providers. 
* [ ] - Inline Role Policy character limit is greater than customer managed policies. Exception handling TBD
* [ ] - Converting Inline Role Policy to Customer Managed Policy and attaching it to a permission set may cause a Permission Set to have more than 20 Customer Managed Policies which is disallowed by Identity Center Quotas. Exception handling is TBD
* [ ] - Not all service resource policy types are supported.
* [ ] - Cross account federated access
  * [ ] - Resource Policy Evaluation
  * [ ] - Cross Account Role Evaluation
* [ ] - Expand CSV to handle assignments
* [ ] - Expand CSV to handle assignments at OU level
* [ ] - Merge multiple CSVs to identify common role names across accounts 
