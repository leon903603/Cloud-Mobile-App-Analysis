if (Test-Path "C:\Program Files\Amazon\AWSCLIV2") { $env:PATH = "C:\Program Files\Amazon\AWSCLIV2;$env:PATH" }
$AWS_REGION = if ($env:AWS_REGION) { $env:AWS_REGION } else { "ap-southeast-2" }
$ACCOUNT_ID = (aws sts get-caller-identity --query Account --output text).Trim()
$ECR_REPO = "cmaa-dynamic-pdf"
$IMAGE_TAG = "latest"
$REPORT_BUCKET = "cmaa-s3-islab-sydney"
$FUNCTION_NAME = "cmaa-dynamic-pdf-report"
$ROLE_NAME = "$FUNCTION_NAME-role"

$IMAGE_URI = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

Write-Host "==> Deploying Dynamic PDF Lambda: Region=$AWS_REGION Account=$ACCOUNT_ID Image=$IMAGE_URI" -ForegroundColor Cyan

# 1. Ensure ECR repository exists
Write-Host "==> Checking ECR repository $ECR_REPO..."
& aws ecr describe-repositories --repository-names $ECR_REPO --region $AWS_REGION *>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "==> Creating ECR repository $ECR_REPO..." -ForegroundColor Yellow
    & aws ecr create-repository --repository-name $ECR_REPO --region $AWS_REGION | Out-Null
} else {
    Write-Host "==> ECR repository $ECR_REPO exists." -ForegroundColor Green
}

# 2. Login to ECR
Write-Host "==> Logging in to ECR..."
$password = & aws ecr get-login-password --region $AWS_REGION
$password | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# 3. Build & push Docker image (using standard docker push for reliable host DNS)
Write-Host "==> Building Docker image locally..." -ForegroundColor Cyan
docker build --provenance=false --sbom=false -f Dockerfile -t $IMAGE_URI .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "==> Pushing image to ECR..." -ForegroundColor Cyan
docker push $IMAGE_URI
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker push failed!" -ForegroundColor Red
    exit 1
}

# 4. Ensure IAM Role exists
Write-Host "==> Checking IAM Role $ROLE_NAME..."
& aws iam get-role --role-name $ROLE_NAME *>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "==> Creating IAM Role $ROLE_NAME..." -ForegroundColor Yellow
    $trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    & aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document $trust | Out-Null
}

& aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole *>$null

$s3Policy = @"
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::$REPORT_BUCKET/*"}
]}
"@
& aws iam put-role-policy --role-name $ROLE_NAME --policy-name S3Access --policy-document $s3Policy *>$null

Write-Host "==> Waiting for IAM propagation (5s)..."
Start-Sleep -Seconds 5

# 5. Create or update Lambda function
$ROLE_ARN = "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
Write-Host "==> Checking Lambda function $FUNCTION_NAME..."
& aws lambda get-function --function-name $FUNCTION_NAME --region $AWS_REGION *>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "==> Updating existing function code..." -ForegroundColor Cyan
    & aws lambda update-function-code --function-name $FUNCTION_NAME --region $AWS_REGION --image-uri $IMAGE_URI | Out-Null
    & aws lambda wait function-updated --function-name $FUNCTION_NAME --region $AWS_REGION
    & aws lambda update-function-configuration --function-name $FUNCTION_NAME --region $AWS_REGION --memory-size 1024 --timeout 120 --environment "Variables={REPORT_BUCKET=$REPORT_BUCKET}" | Out-Null
} else {
    Write-Host "==> Creating new Lambda function $FUNCTION_NAME..." -ForegroundColor Cyan
    & aws lambda create-function --function-name $FUNCTION_NAME --region $AWS_REGION --package-type Image --code "ImageUri=$IMAGE_URI" --role $ROLE_ARN --memory-size 1024 --timeout 120 --environment "Variables={REPORT_BUCKET=$REPORT_BUCKET}" | Out-Null
}

& aws lambda wait function-updated --function-name $FUNCTION_NAME --region $AWS_REGION

Write-Host ""
Write-Host "==> DONE. Dynamic PDF Lambda deployed successfully: $FUNCTION_NAME" -ForegroundColor Green
