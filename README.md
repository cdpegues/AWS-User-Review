# AWS-User-Review
Quick script to streamline the AWS User review process.

Considerations:

Works in Any AWS Account (and Organization): This script works in the context of a single AWS account but should work in an organization if you are using AWS Organizations by running the script on each account in your organization (you can extend it to assume roles in other accounts, if necessary, using cross-account roles).

Handling Group Policies: Now, the script includes policies attached to both users and groups the users belong to, ensuring it checks both sources of policy permissions.

Combining Policies: All user policies (both inline and managed) and group policies are combined into a unique list using set() to avoid duplicates.

IAM Role Policies (Optional): If users have roles and you want to assess their permissions based on assumed roles, you would need to extend this script to include the sts:assumeRole API, which would require handling cross-account role assumptions and retrieving role policies. But for standard IAM users, this script suffices.

Extension for Multiple Accounts (If Using AWS Organizations):

If you're using AWS Organizations and want to pull information from multiple accounts, you'd need to set up cross-account roles in each account, allowing the script to assume the correct role in each member account.

This assume_role function would allow you to switch to any other AWS account in the organization (as long as the cross-account role is set up) and fetch the same IAM data in that account.

Conclusion:

This version of the script checks both user-specific and group-specific policies.

It works for any AWS architecture and can easily be extended to handle multiple accounts if needed.

---

## Usage examples

Run locally using your AWS CLI profile:

```bash
python awsaccessreview.py --profile default --format json --output report.json
```

Run against another account by assuming a cross-account role:

```bash
python awsaccessreview.py --account-id 123456789012 --role OrganizationAccountAccessRole --format json
```

## Required permissions

The IAM principal that runs this script must be able to call the following APIs:

- iam:ListUsers
- iam:ListGroupsForUser
- iam:ListAttachedUserPolicies
- iam:ListUserPolicies
- iam:GetUserPolicy
- iam:GetPolicy
- iam:GetPolicyVersion
- iam:ListAttachedGroupPolicies
- iam:GetGroupPolicy
- iam:ListMFADevices
- iam:ListAccessKeys
- sts:AssumeRole (if using cross-account review)

## Tests

Basic unit tests are provided using `moto`. Run tests with:

```bash
python -m pytest tests/
```
