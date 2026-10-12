#!/usr/bin/env python3
"""
ops/setup_traffic_circuit_breaker.py — Provision CloudWatch Egress Bandwidth Circuit Breaker.

Sets up a CloudWatch Metric Alarm for cmaa-server (i-03d897a7c64334194) in ap-southeast-2.
If NetworkOut exceeds 20 GB in 15 minutes (3 evaluation periods of 5 minutes),
AWS CloudWatch automatically triggers the EC2 stop action to halt runaway egress bandwidth billing.
"""

import boto3
import sys

REGION = "ap-southeast-2"
INSTANCE_ID = "i-03d897a7c64334194"
ALARM_NAME = "CMAA-Server-High-Egress-Circuit-Breaker"
# 20 GB = 21,474,836,480 bytes threshold over 15 minutes (3 * 300s periods)
THRESHOLD_BYTES = 21474836480.0

def provision_circuit_breaker():
    cw = boto3.client("cloudwatch", region_name=REGION)
    
    print(f"[*] Provisioning CloudWatch Alarm '{ALARM_NAME}' for instance {INSTANCE_ID} in {REGION}...")
    
    stop_action = f"arn:aws:automate:{REGION}:ec2:stop"
    
    response = cw.put_metric_alarm(
        AlarmName=ALARM_NAME,
        AlarmDescription="Stops cmaa-server if egress network traffic exceeds 20 GB within 15 minutes to prevent billing overrun.",
        ActionsEnabled=True,
        AlarmActions=[stop_action],
        MetricName="NetworkOut",
        Namespace="AWS/EC2",
        Statistic="Sum",
        Dimensions=[
            {
                "Name": "InstanceId",
                "Value": INSTANCE_ID
            }
        ],
        Period=300, # 5 minutes
        EvaluationPeriods=3, # 3 consecutive periods = 15 minutes
        Threshold=THRESHOLD_BYTES,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching"
    )
    
    print(f"[+] Successfully configured CloudWatch Alarm: {ALARM_NAME}")
    print(f"    Target Instance: {INSTANCE_ID}")
    print(f"    Threshold: {THRESHOLD_BYTES / (1024**3):.1f} GB NetworkOut / 15 mins")
    print(f"    Action: {stop_action}")

if __name__ == "__main__":
    try:
        provision_circuit_breaker()
    except Exception as e:
        print(f"[-] Error setting up circuit breaker: {e}", file=sys.stderr)
        sys.exit(1)
