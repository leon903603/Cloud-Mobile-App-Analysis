#!/usr/bin/env bash
echo "=== 1. Line Counts ==="
wc -l index.ts guest_routes.ts dispatch.ts newebpay.ts credit_audit.ts services/*.ts

echo ""
echo "=== 2(a). Users collection or recordCreditChange occurrences ==="
grep -rnE "collection\([\"']users[\"']\)|recordCreditChange" --include="*.ts" --exclude-dir="tests" --exclude-dir="node_modules" --exclude-dir="dist" .

echo ""
echo "=== 2(b). S3/PDF raw calls or replace(/\.json) ==="
grep -rnE "putFile|putJson|putObject|objectExists|getPresignedDownloadUrl|purgeObjectAllVersions|deleteObject|renderReportPdf|\.replace\(/\\\\\.json" --include="*.ts" --exclude-dir="tests" --exclude-dir="node_modules" --exclude-dir="dist" .

echo ""
echo "=== 2(c). EC2Client or secretbox calls ==="
grep -rnE "EC2Client|StartInstancesCommand|StopInstancesCommand|unseal\(|seal\(" --include="*.ts" --exclude-dir="tests" --exclude-dir="node_modules" --exclude-dir="dist" .
