#!/usr/bin/env python3
"""
ops/rollback_platform.py — One-click Rollback Script for CMAA Platform.

Allows instant rollback of both local and remote EC2 deployment to a specific Git commit or tag.

Usage:
    python ops/rollback_platform.py                    # Rolls back to v3-baseline-44d9607
    python ops/rollback_platform.py <commit_or_tag>    # Rolls back to specific commit/tag
"""

import sys
import subprocess
import boto3

DEFAULT_ROLLBACK_TARGET = "v3-baseline-44d9607"
REGION = "ap-southeast-2"
INSTANCE_ID = "i-03d897a7c64334194"

def rollback(target_ref):
    print(f"==================================================")
    print(f"[*] Starting CMAA Rollback to: {target_ref}")
    print(f"==================================================")

    # 1. Local rollback check
    print(f"[1/3] Resetting local repository to {target_ref}...")
    try:
        subprocess.run(["git", "checkout", "main"], check=True)
        subprocess.run(["git", "reset", "--hard", target_ref], check=True)
        subprocess.run(["git", "push", "origin", "main", "--force"], check=True)
        print(f"[+] Local repo and remote 'main' successfully reverted to {target_ref}.")
    except Exception as e:
        print(f"[-] Local git rollback failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. AWS EC2 SSM Rollback command
    print(f"[2/3] Triggering remote rollback on EC2 instance {INSTANCE_ID} via AWS SSM...")
    try:
        ssm = boto3.client("ssm", region_name=REGION)
        commands = [
            "cd /home/ubuntu/Cloud-Mobile-App-Analysis",
            "git fetch origin",
            "git checkout main",
            f"git reset --hard {target_ref}",
            "docker compose down",
            "docker compose up -d --build"
        ]
        
        resp = ssm.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [" && ".join(commands)]}
        )
        command_id = resp["Command"]["CommandId"]
        print(f"[+] Remote rollback initiated! SSM Command ID: {command_id}")
        print(f"[3/3] Deployment rollback is running in the background on EC2.")
        print(f"      Check status anytime with:")
        print(f"      aws ssm get-command-invocation --command-id {command_id} --instance-id {INSTANCE_ID} --region {REGION}")
    except Exception as e:
        print(f"[-] EC2 SSM invocation failed: {e}", file=sys.stderr)
        print(f"[!] Please ensure EC2 instance is running and AWS CLI credentials have SSM access.")
        sys.exit(1)

    print(f"\n[✓] Rollback sequence completed successfully.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROLLBACK_TARGET
    rollback(target)
