if (Test-Path "C:\Program Files\Amazon\AWSCLIV2") { $env:PATH = "C:\Program Files\Amazon\AWSCLIV2;$env:PATH" }
$AWS_REGION = if ($env:AWS_REGION) { $env:AWS_REGION } else { "ap-southeast-2" }
$ACCOUNT_ID = (aws sts get-caller-identity --query Account --output text).Trim()
$ECR_REPO = "cmaa-static-pdf"
$IMAGE_TAG = "latest"
$REPORT_BUCKET = "cmaa-s3-islab-sydney"
$FUNCTION_NAME = "cmaa-static-pdf-report"
$ROLE_NAME = "$FUNCTION_NAME-role"

$IMAGE_URI = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

Write-Host "==> Deploying Static PDF Lambda: Region=$AWS_REGION Account=$ACCOUNT_ID Image=$IMAGE_URI" -ForegroundColor Cyan

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

# 3. Build & push Docker image
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

$ROLE_ARN = "arn:aws:iam::${ACCOUNT_ID}:role/$ROLE_NAME"
Start-Sleep -Seconds 5

# 5. Create or Update Lambda Function
Write-Host "==> Checking Lambda function $FUNCTION_NAME..."
& aws lambda get-function --function-name $FUNCTION_NAME --region $AWS_REGION *>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "==> Creating Lambda function $FUNCTION_NAME..." -ForegroundColor Yellow
    & aws lambda create-function `
        --function-name $FUNCTION_NAME `
        --package-type Image `
        --code ImageUri=$IMAGE_URI `
        --role $ROLE_ARN `
        --timeout 60 `
        --memory-size 1024 `
        --environment "Variables={REPORT_BUCKET=$REPORT_BUCKET}" `
        --region $AWS_REGION
} else {
    Write-Host "==> Updating Lambda function code..." -ForegroundColor Yellow
    & aws lambda update-function-code `
        --function-name $FUNCTION_NAME `
        --image-uri $IMAGE_URI `
        --region $AWS_REGION | Out-Null
    
    Start-Sleep -Seconds 5
    & aws lambda update-function-configuration `
        --function-name $FUNCTION_NAME `
        --timeout 60 `
        --memory-size 1024 `
        --environment "Variables={REPORT_BUCKET=$REPORT_BUCKET}" `
        --region $AWS_REGION | Out-Null
}

Write-Host "==> Deployment complete for $FUNCTION_NAME!" -ForegroundColor Green
