"""
# Migration Evaluator for AWS IAM Identity Center (IdC ME)

## Authors 
* Jonathan VanKim
* Valentine Reid

## Disclaimer

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""

import boto3
import pprint
import json
import random
import string
import csv

### Troposphere - outputs cloudformation json or yaml
from troposphere import Template, Parameter, Sub
from troposphere.iam import Policy

from typing import Dict, List

client = boto3.client('iam')
iam = boto3.resource('iam')

def get_federated_arn_to_migrate() -> List[str]:
    """
    List identity provider ARNs and prompt user to select 
    an arn and return federated_arn_to_migrate list_saml_providers
    """
    federated_role_arn = []
    federated_roles = client.list_saml_providers()
    response_federated_role_arns = [r.get('Arn') for r in federated_roles.get('SAMLProviderList')]
    
    user_input = ''

    input_message = "Pick an option:\n"

    for index, item in enumerate(response_federated_role_arns):
        input_message += f'{index+1}) {item}\n'

    input_message += 'Your choice: '

    while user_input not in map(str, range(1, len(response_federated_role_arns) + 1)):
        user_input = input(input_message)

    federated_arn_to_migrate = response_federated_role_arns[int(user_input) - 1]
    """
    #Uncomment this block to report which ARN was
    print(federated_arn_to_migrate)
    """
    return federated_arn_to_migrate

### This code gets returns all roles
def get_role_names() -> List[str]:
    """ Retrieve a list of role names by paginating over list_roles() calls """
    role_names = []
    role_paginator = client.get_paginator('list_roles')
    for response in role_paginator.paginate():
        response_role_names = [r.get('RoleName') for r in response['Roles']]
        role_names.extend(response_role_names)
        pprint.pp(role_names)
    return role_names

def get_roles_with_trust_policy(role_names, arn_saml_provider):
    """
    Take role_names and filter roles with federated trust policy of arn 
    selected in prior function and return federated_role_names
    """
    
    role_list = []

    """
    # Uncomment this section to report which SAML provider was passed
    # to this function
    print("Looking for this SAML provider:  " + arn_saml_provider)
    """
    for r in role_names:
        # print("This is what R is:  "  + r)
        role = iam.Role(r)
        
        policy_doc = role.assume_role_policy_document

        # Debugging
        # print(json.dumps(policy_doc, indent=4))
        # print(type(policy_doc))

        try: 
            role_saml = json.dumps(policy_doc['Statement'][0]['Principal']['Federated'], indent=4)
        except:
            """
            #Uncomment this section to report the exception" 
            print("Federated trust policy NOT found.")
            """
            role_saml = ""
        else:
            """
            #Uncomment this section to report the role being evaluated
            print("Federated role is:  " +  role.arn)
            """
            if policy_doc['Statement'][0]['Principal']['Federated'] == arn_saml_provider:
                """
                #Uncomment this section to report the SAML provider was found
                #and the list of roles with the trust policy
                print("SAML provider found in trust policy:  " + r)
                print("role list:  ")
                print(role_list)
                """
                role_list.append(r)

    return role_list

def get_attached_policies_for_roles(role_names: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """ 
        Create a mapping of role names and any policies they have attached to them by 
        paginating over list_attached_role_policies() calls for each role name. 
        Attached policies will include policy name and ARN.
    """

    attached_policy_map = {}
    attached_policy_paginator = client.get_paginator('list_attached_role_policies')
    for name in role_names:
        role_policies = []
        for response in attached_policy_paginator.paginate(RoleName=name):
            """
            If assume_role_policy_document contains federated_arn_to_migrate
            then perform the following
            """
            role_policies.extend(response.get('AttachedPolicies'))
        attached_policy_map.update({name: role_policies})
        """
        #Uncomment this to print the map of attached policies to roles
        pprint.pp(attached_policy_map)
        """
    return attached_policy_map

def get_inline_policies_for_roles(role_names: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """ 
        Create a mapping of role names and inline policy role names
    """
    """
    #Uncomment this to print the name of the roles being processed
    print("Incoming rolenames:  " + json.dumps(role_names))
    """
    inline_policy_map = {}
    inline_policy_paginator = client.get_paginator('list_role_policies')


    # Builds one cfn template per role regardless of number of inline policies
    for name in role_names:
        # Troposhere setup
        template = Template()
        template.set_version("2012-10-17")
        y = 0
        inline_role_policies = []
        cmp_inline_role_policies_name = []        
        for response in inline_policy_paginator.paginate(RoleName=name):
            """
            #Uncomment this section to print the inline policy to screen
            print("Response:  " + response)
            """
            inline_role_policies.extend(response.get('PolicyNames'))
        inline_policy_map.update({name: inline_role_policies})
        
        cfn_description = 'Policy built from inline policy attached to role - ' + name + '.'
        template.set_description(cfn_description)
        
        # Iterates through all of the inline policies and builds a cfn template
        for x in inline_policy_map[name]:

            inline_policy = client.get_role_policy(RoleName=name,PolicyName=x)
            """
            #Uncomment this section to print the inline policy JSON
            print ("Inline Policy:  ")
            pprint.pp(inline_policy)
            """
            # This returns a list of all the inline policy names for
            # use in the CSV output file            
            cmp_name = inline_policy['PolicyName']
            cmp_inline_role_policies_name.append(name + ', ' + cmp_name)            


            y = (y+1)  #increment to keep resources unique
            template.add_resource(
                Policy(
                    'rCMP' + str(y),
                    PolicyName = cmp_name,
                    PolicyDocument = inline_policy['PolicyDocument']
                )
            )
            # to_json or to_yaml for output
            #pprint.pp(template.to_yaml())
            #return template.to_json()
            ## To Do Write template.to_yaml to a json file with name

            ## This return is used for csv building
            return cmp_inline_role_policies_name  

def get_role_names_greaterthan_32char(role_names: List[str]) -> Dict[str, List[Dict[str, str]]]:
    role_names_greaterthan_32char = []
    for name in role_names:
        # If the role name is greater than or equal to 32 characters the 
        # role name can not be used for a permission set. This section 
        # sets the permission set name in the CSV to the first 27 characters
        # and adds 3 random alphanumaric characters plus an underscore
        # This code doesn't have collision logic as there are 56^3 
        # random strings that can be generated.
        if len(name) >= 32:            
            short_role_name = name[0:27]
            random_length = 3
            random_string = ''.join(random.choices(string.ascii_uppercase +
                             string.digits + string.ascii_lowercase, k=random_length))
            shortened_role_name = short_role_name + '_' +  random_string
            roles_greaterthan_32char_csv = name + ', ' + shortened_role_name
            role_names_greaterthan_32char.append(roles_greaterthan_32char_csv)
        else:
            continue
    return role_names_greaterthan_32char

def get_role_names() -> List[str]:
    """ Retrieve a list of role names by paginating over list_roles() calls """
    role_names = []
    role_paginator = client.get_paginator('list_roles')
    for response in role_paginator.paginate():
        response_role_names = [r.get('RoleName') for r in response['Roles']]
        role_names.extend(response_role_names)
        """
        # Uncomment this to print all roles in an AWS Account
        pprint.pp(role_names)
        """
    return role_names

def get_sqs_queues(aws_account_number, role_names):
    """
    Creates an iterable of all Queue resources in the collection.
    """
    ssm_client = boto3.client('ssm')
    short_region = set()
    # Search for SQS in all regions.
    # There is a public parameter of all regions in AWS that is managed
    # by AWS, and therefore, this code block ensures that this function  
    # always searches all AWS regions at runtime.
    # https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-public-parameters-global-infrastructure.html
    for page in ssm_client.get_paginator('get_parameters_by_path').paginate(
        Path='/aws/service/global-infrastructure/regions'
    ):
        short_region.update(p['Value'] for p in page['Parameters'])

    try:
        ### Set the header for the CSV file
        header = ['RoleArn', 'SQSQueueUrl']
        f = open('resource_policies_to_migrate_' + aws_account_number + '_sqs' + '.csv', 'w', newline='')
        writer = csv.writer(f)

        # write the header
        writer.writerow(header)
        sqs_policies = []
        for region in short_region:
            try: 
                sqs = boto3.resource("sqs", region_name=region)
                for queue in sqs.queues.all():
                    # check if exists a queue policy
                    queue_policy = json.loads(queue.attributes.get('Policy'))
                    queue_policy = queue_policy['Statement']
                    """
                    # Uncomment this to get the Queue Policy Principal"
                    pprint.pp(queue_policy[0]['Principal'])
                    """
                    #  For each queue policy and for each role (filtered role list), 
                    #  does the role arn match the role arn in the policy?
                    for policy in queue_policy:
                        # print("This is the queue's principal:  ")
                        # pprint.pp(policy['Principal'])
                        # look for principal arn
                        for r in role_names:
                            role_arn = iam.Role(r)
                            # Uncomment this to determine what roles and SQS queues are being evaluated
                            # print("This is what role is and queue principal:  ")
                            # pprint.pp(role_arn.arn)
                            # pprint.pp(policy['Principal']['AWS'])
                            
                            # print("This is what role is:  ")
                            # print(role_arn)
                            # print("This is the queue")
                            # print(queue)
                            
                            # Does principla arn match filtered role name arn list?
                            if role_arn.arn == policy['Principal']['AWS']:
                            
                                # Uncomment this to print matches
                                # print("ROLE ARN MATCHES SQS PRINCIPAL!!!")
                                # pprint.pp(role_arn.arn)
                                # pprint.pp(queue)

                                role_arn = role_arn.arn
                                # create list for csv
                                sqs_policies.append(role_arn)
                                sqs_policies.append(queue)
                                # pprint.pp(sqs_policies)
                                # write multiple row
                                writer.writerow(sqs_policies)
            except Exception as err:
                pass
    except ClientError:
        logger.exception('Could not list queues.')
        raise
    else:
        f.close()
        print('CSV created identity_center_import_' + aws_account_number + '_sqs' + '.csv')
        return sqs_policies

def get_role_permissions_boundary(role_name):
    # This determines if a role has a permission boundary or not. 
    permission_boundary_name = []
    for role in role_name:
        response = client.get_role(RoleName = role)
        #pprint.pp(response)
        try:
            #pprint.pp(response['Role']['PermissionsBoundary'])
            permission_boundary = response['Role']['PermissionsBoundary']['PermissionsBoundaryArn']
            permission_boundary_with_role = role + ", " + permission_boundary
            permission_boundary_name.append(permission_boundary_with_role)
        ## This handles null cases so CSV is populated
        except:
            permission_boundary_with_role = role + ", " + "no_permission_boundary"
            permission_boundary_name.append(permission_boundary_with_role)
    return permission_boundary_name

def get_aws_account_number():
    # This gets the AWS Account Number
    aws_account_number = boto3.client('sts').get_caller_identity().get('Account')
    return(aws_account_number)

def generate_csv(aws_account_number, filtered_federated_roles, permission_boundary, attached_role_policies, inline_role_policies, role_names_greaterthan_32char):


    # The way this function works is by iteratively building each column in the CSV from the prior functions
    # The primary key used to match values in _most_ situations is the IAM Role Name
    # pb = IAM Permission Boundary
    # psn = Identity Center Permission Set Name
    csv_output = []
    role_policies_list = []
    role_policies_list_with_pb = []
    role_policies_list_with_pb_with_psn = []   
    role_policies_list_with_pb_with_psn_with_account = []
    role_policies_list_with_pb_with_psn_with_account.append('Role, Policy Name, CMP/AMP, Permission Boundary, CMP/AMP, Permission Set Name, Account Number')

    for item in filtered_federated_roles: 
        if item in attached_role_policies:
            for policy in attached_role_policies[item]:
                if policy['PolicyArn'].__contains__('arn:aws:iam::aws:policy'):
                    role_policies_list.append(item + ', ' + str(policy['PolicyName']) + ', amp')
                else:
                    role_policies_list.append(item + ', ' + str(policy['PolicyName']) + ', cmp')

# Confirm the inline role policy name is the same as what is being created by cfn in an earlier function
# This combines inline policies with attached policies
# This assumes a customer makes a CMP from the inline policy with the same name
    for item in inline_role_policies:
        role_policies_list.append(item + ', cmp')


# This adds permission boundary information to the role_policy_list
    for item in permission_boundary:
        item_list = list(item.split(', '))
        for role in role_policies_list:
            role_list = list(role.split(', '))
# item_list[0] and role_list[0] are both the role name. This is used to match two lists together
            if item_list[1] == 'no_permission_boundary' and item_list[0] == role_list[0]:
                role_policies_list_with_pb.append(role + ', no_permission_boundary, none')
            elif item_list[1].__contains__('arn:aws:iam') and item_list[0] == role_list[0]:
## This trims the ARN of the PB and sets item_str to the policy name of the pb
## This is done by trimming the characters left of the \ in the ARN (including \)
                if item_list[1].__contains__('arn:aws:iam::aws:policy'):
                    item_str = item_list[1]
                    item_str = item_str[25:]
                    role_policies_list_with_pb.append(role + ', ' + item_str + ', amp')
                else:
                    item_str = item_list[1]
                    item_str = item_str[33:]
                    role_policies_list_with_pb.append(role + ', ' + item_str + ', cmp')
#    print(role_policies_list_with_pb)

### This section takes all the roles with pbs and attaches shortened permission set names to it if it's longer than 32 char
    for role in role_policies_list_with_pb[:]:
        role_list = list(role.split(', '))
        for item in role_names_greaterthan_32char:
            item_list = list(item.split(', '))
            if item_list[0] == role_list[0]:
                role_policies_list_with_pb_with_psn.append(role + ', ' + item_list[1])
## This remove allows the rest of the role policies less than 32char to be evaluated 
                role_policies_list_with_pb.remove(role)

### This section adds the rest of the roles <32 to roles with permission set names
    for role in role_policies_list_with_pb:
        role_list = list(role.split(', '))
        role_policies_list_with_pb_with_psn.append(role + ', ' + role_list[0])


### This section adds account numbers
    for role in role_policies_list_with_pb_with_psn:
        role_policies_list_with_pb_with_psn_with_account.append(role + ', ' + aws_account_number)

### This creates a csv file
    file=open('identity_center_import_' + aws_account_number + '.csv', 'w')
    for role in role_policies_list_with_pb_with_psn_with_account: 
        file.writelines(role+'\n')
    file.close()
    print('CSV created identity_center_import_' + aws_account_number + '.csv')



#  The main functions are called below.
######################################################################################

# Get AWS Account number
aws_account_number = get_aws_account_number()

#  Get all of the SAML IdP and ask the user to pick one.
#  The SAML IdP and roles associated with it is what we target for data extraction.
federated_roles = get_federated_arn_to_migrate()
print('This is ARN of the SAML provider selected:  ' + federated_roles)

#  Get a list of all the roles in the account
role_names = get_role_names()

#  Figure out which of the roles are federated roles that has the SAML IdP selected by the user
filtered_federated_roles = get_roles_with_trust_policy(role_names, federated_roles)

#  Pass in the list of filtered federated roles and see which ones have inline policies
inline_role_policies = get_inline_policies_for_roles(filtered_federated_roles)

#  Pass in the list of filtered federated roles and see which ones have attached policies
attached_role_policies = get_attached_policies_for_roles(filtered_federated_roles)

#  Pass in the list of filtered federated roles and see which ones have permission boundary policies
perm_boundaries_policies = get_role_permissions_boundary(filtered_federated_roles)

#  SQS resource policies may have a specific principal specified.  Does it match with any principals you want to migrate?
#  If so, you will need to update the policy to ensure IDC managed roles maintain access.
sqs_queues_with_matching_principals = get_sqs_queues(aws_account_number, filtered_federated_roles)

#  Get role names greater than 32char
role_names_greaterthan_32char = get_role_names_greaterthan_32char(filtered_federated_roles)

# Get list of permission boundary names
permission_boundary = get_role_permissions_boundary(filtered_federated_roles)

# Generate CSV
generate_csv_for_idc = generate_csv(aws_account_number, filtered_federated_roles, permission_boundary, attached_role_policies, inline_role_policies, role_names_greaterthan_32char)



