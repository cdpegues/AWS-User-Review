#!/usr/bin/env python3
"""AWS IAM user access review

This script enumerates IAM users, their groups, attached/inline policies,
policy documents, and some user metadata and can output JSON for further analysis.

Improvements over the original include:
- Use of paginators and error handling
- Retrieval of managed policy documents and inline policy documents
- Collection of user metadata: CreateDate, PasswordLastUsed, MFA devices, access keys
- Logging and a simple CLI with JSON output
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger(__name__)


def get_boto3_session(profile: str | None = None) -> boto3.Session:
    """Return a boto3 Session. Specify a profile if needed."""
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def assume_role(session: boto3.Session, account_id: str, role_name: str = "OrganizationAccountAccessRole") -> boto3.client:
    """Assume a role in a different AWS account and return an IAM client using temporary creds."""
    sts = session.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="CrossAccountIAMSession")
        creds = resp["Credentials"]
        return boto3.client(
            "iam",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError as e:
        LOG.exception("Failed to assume role %s in account %s: %s", role_name, account_id, e)
        raise


def list_users(iam_client) -> List[Dict]:
    """List all IAM users (returns list of user dicts). Uses paginator."""
    users: List[Dict] = []
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except ClientError:
        LOG.exception("Failed to list users")
        raise
    return users


def list_attached_user_policies(iam_client, user_name: str) -> List[Dict]:
    policies: List[Dict] = []
    try:
        paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=user_name):
            policies.extend(page.get("AttachedPolicies", []))
    except ClientError:
        LOG.exception("Failed to list attached user policies for %s", user_name)
    return policies


def list_inline_user_policies(iam_client, user_name: str) -> List[str]:
    policy_names: List[str] = []
    try:
        paginator = iam_client.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=user_name):
            policy_names.extend(page.get("PolicyNames", []))
    except ClientError:
        LOG.exception("Failed to list inline user policies for %s", user_name)
    return policy_names


def list_groups_for_user(iam_client, user_name: str) -> List[Dict]:
    groups: List[Dict] = []
    try:
        paginator = iam_client.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=user_name):
            groups.extend(page.get("Groups", []))
    except ClientError:
        LOG.exception("Failed to list groups for user %s", user_name)
    return groups


def list_attached_group_policies(iam_client, group_name: str) -> List[Dict]:
    policies: List[Dict] = []
    try:
        paginator = iam_client.get_paginator("list_attached_group_policies")
        for page in paginator.paginate(GroupName=group_name):
            policies.extend(page.get("AttachedPolicies", []))
    except ClientError:
        LOG.exception("Failed to list attached group policies for %s", group_name)
    return policies


def get_managed_policy_document(iam_client, policy_arn: str) -> Dict:
    """Retrieve the policy document for a managed policy (latest/default version)."""
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        default_version_id = policy.get("DefaultVersionId")
        if default_version_id:
            version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
            return version.get("PolicyVersion", {}).get("Document", {})
    except ClientError:
        LOG.exception("Failed to fetch managed policy document for %s", policy_arn)
    return {}


def get_inline_user_policy_document(iam_client, user_name: str, policy_name: str) -> Dict:
    try:
        resp = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
        return resp.get("PolicyDocument", {})
    except ClientError:
        LOG.exception("Failed to fetch inline user policy %s for %s", policy_name, user_name)
    return {}


def get_inline_group_policy_document(iam_client, group_name: str, policy_name: str) -> Dict:
    try:
        resp = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
        return resp.get("PolicyDocument", {})
    except ClientError:
        LOG.exception("Failed to fetch inline group policy %s for group %s", policy_name, group_name)
    return {}


def list_mfa_devices(iam_client, user_name: str) -> List[Dict]:
    try:
        paginator = iam_client.get_paginator("list_mfa_devices")
        devices: List[Dict] = []
        for page in paginator.paginate(UserName=user_name):
            devices.extend(page.get("MFADevices", []))
        return devices
    except ClientError:
        LOG.exception("Failed to list MFA devices for %s", user_name)
    return []


def list_access_keys(iam_client, user_name: str) -> List[Dict]:
    try:
        paginator = iam_client.get_paginator("list_access_keys")
        keys: List[Dict] = []
        for page in paginator.paginate(UserName=user_name):
            keys.extend(page.get("AccessKeyMetadata", []))
        return keys
    except ClientError:
        LOG.exception("Failed to list access keys for %s", user_name)
    return []


def policy_has_wildcard_allow(policy_doc: Dict) -> bool:
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action")
        resources = s.get("Resource")
        if actions == "*" or resources == "*":
            return True
        if isinstance(actions, list) and "*" in actions:
            return True
        if isinstance(resources, list) and "*" in resources:
            return True
    return False


def build_user_report(iam_client) -> Dict[str, Dict]:
    report: Dict[str, Dict] = {}
    users = list_users(iam_client)

    # cache group attached policy arn lists
    group_attached_cache: Dict[str, List[Dict]] = {}

    for u in users:
        user_name = u.get("UserName")
        if not user_name:
            continue

        user_info: Dict = {
            "UserName": user_name,
            "CreateDate": u.get("CreateDate"),
            "PasswordLastUsed": u.get("PasswordLastUsed"),
            "Groups": [],
            "AttachedPolicies": [],  # managed attached policies (with ARN)
            "InlinePolicies": {},  # name->doc
            "GroupPolicies": [],  # list of attached policy ARNs from groups
            "MFADevices": [],
            "AccessKeys": [],
            "Risk": {},
        }

        # attached managed + inline
        attached = list_attached_user_policies(iam_client, user_name)
        for a in attached:
            user_info["AttachedPolicies"].append({"PolicyArn": a.get("PolicyArn"), "PolicyName": a.get("PolicyName")})
            # try fetch doc
            if a.get("PolicyArn"):
                doc = get_managed_policy_document(iam_client, a.get("PolicyArn"))
                if doc:
                    risky = policy_has_wildcard_allow(doc)
                    if risky:
                        user_info["Risk"].setdefault("WildcardPolicies", []).append(a.get("PolicyArn"))

        for inline_name in list_inline_user_policies(iam_client, user_name):
            doc = get_inline_user_policy_document(iam_client, user_name, inline_name)
            user_info["InlinePolicies"][inline_name] = doc
            if doc and policy_has_wildcard_allow(doc):
                user_info["Risk"].setdefault("WildcardInlinePolicies", []).append(inline_name)

        # groups + group policies
        groups = list_groups_for_user(iam_client, user_name)
        for g in groups:
            gname = g.get("GroupName")
            user_info["Groups"].append(gname)
            if gname not in group_attached_cache:
                group_attached_cache[gname] = list_attached_group_policies(iam_client, gname)
            for gp in group_attached_cache[gname]:
                user_info["GroupPolicies"].append({"PolicyArn": gp.get("PolicyArn"), "PolicyName": gp.get("PolicyName")})
                if gp.get("PolicyArn"):
                    doc = get_managed_policy_document(iam_client, gp.get("PolicyArn"))
                    if doc and policy_has_wildcard_allow(doc):
                        user_info["Risk"].setdefault("WildcardGroupPolicies", []).append(gp.get("PolicyArn"))

        # mfa
        user_info["MFADevices"] = list_mfa_devices(iam_client, user_name)

        # access keys
        aks = list_access_keys(iam_client, user_name)
        user_info["AccessKeys"] = aks

        report[user_name] = user_info

    return report


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS IAM user access review")
    parser.add_argument("--profile", help="AWS CLI profile to use", default=None)
    parser.add_argument("--account-id", help="If set, assume role into target account and run review there", default=None)
    parser.add_argument("--role", help="Role name to assume (if --account-id)", default="OrganizationAccountAccessRole")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--output", help="Path to write JSON output (if --format json)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    session = get_boto3_session(args.profile)

    if args.account_id:
        iam_client = assume_role(session, args.account_id, role_name=args.role)
    else:
        iam_client = session.client("iam")

    LOG.info("Starting IAM user access review")
    report = build_user_report(iam_client)

    if args.format == "text":
        for uname, info in report.items():
            print(f"User: {uname}")
            print(f"  Created: {info.get('CreateDate')}")
            print(f"  PasswordLastUsed: {info.get('PasswordLastUsed')}")
            print(f"  Groups: {', '.join(info.get('Groups', [])) or 'No groups'}")
            attached = [a.get('PolicyArn') or a.get('PolicyName') for a in info.get('AttachedPolicies', [])]
            print(f"  Attached policies: {', '.join(attached) if attached else 'No attached policies'}")
            print(f"  Inline policies: {', '.join(info.get('InlinePolicies', {}).keys()) if info.get('InlinePolicies') else 'No inline policies'}")
            if info.get("Risk"):
                print(f"  Risks: {json.dumps(info.get('Risk'))}")
            print("-" * 60)
    else:
        output_json = json.dumps(report, default=str, indent=2)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(output_json)
            LOG.info("Wrote JSON report to %s", args.output)
        else:
            print(output_json)

    LOG.info("Finished IAM user access review")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
