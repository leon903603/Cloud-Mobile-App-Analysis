#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:=ap-southeast-2}"
: "${ACCOUNT_ID:=$(aws sts get-caller-identity --query Account --output text)}"
: "${ECR_REPO:=cmaa-pdf}"
: "${IMAGE_TAG:=latest}"
: "${REPORT_BUCKET:=cmaa-s3-islab-sydney}"
: "${FUNCTION_NAME:=cmaa-pdf-report}"
: "${ROLE_NAME:=${FUNCTION_NAME}-role}"

IMAGE_URI="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

echo "==> Deploying PDF Lambda: Region=$AWS_REGION Account=$ACCOUNT_ID Image=$IMAGE_URI"

aws ecr describe-repositories --repository-names "$ECR_REPO" --region "$AWS_REGION" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name "$ECR_REPO" --region "$AWS_REGION" >/dev/null
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  -f lambda/Dockerfile -t "$IMAGE_URI" --push .

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1 \
  || aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "$TRUST" >/dev/null
aws iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null

aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name S3Access --policy-document "$(cat <<JSON
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::${REPORT_BUCKET}/*"}
]}
JSON
)"

echo "==> waiting for IAM propagation"; sleep 10

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNCTION_NAME" --region "$AWS_REGION" \
    --image-uri "$IMAGE_URI" >/dev/null
  aws lambda wait function-updated --function-name "$FUNCTION_NAME" --region "$AWS_REGION"
  aws lambda update-function-configuration --function-name "$FUNCTION_NAME" --region "$AWS_REGION" \
    --memory-size 512 --timeout 120 --environment "Variables={REPORT_BUCKET=${REPORT_BUCKET}}" >/dev/null
else
  aws lambda create-function --function-name "$FUNCTION_NAME" --region "$AWS_REGION" \
    --package-type Image --code "ImageUri=${IMAGE_URI}" \
    --role "$ROLE_ARN" --memory-size 512 --timeout 120 \
    --environment "Variables={REPORT_BUCKET=${REPORT_BUCKET}}" >/dev/null
fi
aws lambda wait function-updated --function-name "$FUNCTION_NAME" --region "$AWS_REGION"

echo ""
echo "==> DONE. PDF Lambda deployed successfully: $FUNCTION_NAME"
