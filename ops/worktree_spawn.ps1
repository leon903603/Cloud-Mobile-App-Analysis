<#
.SYNOPSIS
    Spawns an isolated Git Worktree for Cloud-Mobile-App-Analysis with dedicated environment and DB.

.DESCRIPTION
    Creates a new Git Worktree under Cloud-Mobile-App-Analysis/.worktrees/<WorktreeName>,
    configures an isolated .env with unique PORT and SQLITE_PATH to prevent database locks,
    and runs npm ci in the server directory.

.PARAMETER WorktreeName
    The name of the worktree folder (e.g., 'pf-node', 'agent-test').

.PARAMETER BranchName
    The branch to create or checkout. Defaults to 'feat/<WorktreeName>'.

.PARAMETER BaseBranch
    Base branch to branch off from if the target branch does not exist yet. Default: 'main'.

.PARAMETER Port
    Express server port for this worktree to avoid port conflicts. Default: 3002.

.PARAMETER SkipInstall
    Skip running 'npm ci' after worktree checkout.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$WorktreeName,

    [Parameter(Position = 1)]
    [string]$BranchName = "",

    [Parameter()]
    [string]$BaseBranch = "main",

    [Parameter()]
    [int]$Port = 3002,

    [Parameter()]
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$RepoPath = Join-Path $ProjectRoot "Cloud-Mobile-App-Analysis"

if (-not (Test-Path (Join-Path $RepoPath ".git"))) {
    Write-Error "Target repository not found or not a Git repo at: $RepoPath"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($BranchName)) {
    $BranchName = "feat/$WorktreeName"
}

$WorktreesRoot = Join-Path $RepoPath ".worktrees"
if (-not (Test-Path $WorktreesRoot)) {
    New-Item -ItemType Directory -Path $WorktreesRoot -Force | Out-Null
}

$TargetWorktreePath = Join-Path $WorktreesRoot $WorktreeName

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Spawning CMAA Isolated Worktree: $WorktreeName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[+] Repository:   $RepoPath"
Write-Host "[+] Target Path:  $TargetWorktreePath"
Write-Host "[+] Branch:       $BranchName (Base: $BaseBranch)"
Write-Host "[+] Server Port:  $Port"

# Check if worktree already exists
$ExistingWorktrees = git -C $RepoPath worktree list --porcelain
if ($ExistingWorktrees -match [regex]::Escape($TargetWorktreePath)) {
    Write-Warning "Worktree already registered at $TargetWorktreePath"
} else {
    Write-Host "[*] Creating Git worktree..." -ForegroundColor Yellow
    
    # Check if branch already exists
    $BranchExists = git -C $RepoPath branch --list $BranchName
    if ($BranchExists) {
        git -C $RepoPath worktree add ".worktrees/$WorktreeName" $BranchName
    } else {
        git -C $RepoPath worktree add -b $BranchName ".worktrees/$WorktreeName" $BaseBranch
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create git worktree."
        exit $LASTEXITCODE
    }
}

# Configure isolated .env files
Write-Host "[*] Configuring isolated environment variables..." -ForegroundColor Yellow

$SourceRootEnv = Join-Path $RepoPath ".env"
$TargetRootEnv = Join-Path $TargetWorktreePath ".env"
$SourceServerEnv = Join-Path $RepoPath "server\.env"
$TargetServerEnv = Join-Path $TargetWorktreePath "server\.env"

function Update-EnvFile {
    param(
        [string]$Src,
        [string]$Dst,
        [int]$NewPort,
        [string]$SqliteDbName
    )
    $lines = @()
    if (Test-Path $Src) {
        $lines = Get-Content $Src
    }

    $hasPort = $false
    $hasSqlite = $false
    $outputLines = [System.Collections.Generic.List[string]]::new()

    foreach ($line in $lines) {
        if ($line -match "^PORT=") {
            $outputLines.Add("PORT=$NewPort")
            $hasPort = $true
        } elseif ($line -match "^SQLITE_PATH=") {
            $outputLines.Add("SQLITE_PATH=./data/$SqliteDbName")
            $hasSqlite = $true
        } else {
            $outputLines.Add($line)
        }
    }

    if (-not $hasPort) {
        $outputLines.Add("PORT=$NewPort")
    }
    if (-not $hasSqlite) {
        $outputLines.Add("SQLITE_PATH=./data/$SqliteDbName")
    }

    $dstDir = Split-Path -Parent $Dst
    if (-not (Test-Path $dstDir)) {
        New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    }
    Set-Content -Path $Dst -Value $outputLines -Encoding utf8
}

$DbFileName = "cmaa_${WorktreeName}.db"
Update-EnvFile -Src $SourceRootEnv -Dst $TargetRootEnv -NewPort $Port -SqliteDbName $DbFileName
Update-EnvFile -Src $SourceServerEnv -Dst $TargetServerEnv -NewPort $Port -SqliteDbName $DbFileName

Write-Host "    -> Root .env configured with PORT=$Port and SQLITE_PATH=./data/$DbFileName" -ForegroundColor Green
Write-Host "    -> Server .env configured with PORT=$Port and SQLITE_PATH=./data/$DbFileName" -ForegroundColor Green

# Ensure data directory exists in target worktree server
$TargetDataDir = Join-Path $TargetWorktreePath "server\data"
if (-not (Test-Path $TargetDataDir)) {
    New-Item -ItemType Directory -Path $TargetDataDir -Force | Out-Null
}

# Run npm ci in server directory
if (-not $SkipInstall) {
    $ServerDir = Join-Path $TargetWorktreePath "server"
    Write-Host "[*] Running npm ci in $ServerDir (native Node compilation for better-sqlite3)..." -ForegroundColor Yellow
    Push-Location $ServerDir
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "npm ci exited with non-zero code ($LASTEXITCODE). You may need to run npm install manually."
        } else {
            Write-Host "[+] npm ci completed successfully." -ForegroundColor Green
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[*] SkipInstall switch set; skipped npm ci." -ForegroundColor DarkGray
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Worktree Setup Complete!" -ForegroundColor Green
Write-Host " Worktree Path: $TargetWorktreePath" -ForegroundColor White
Write-Host " Test command:  cd `"$TargetWorktreePath\server`"; npm run test:unit" -ForegroundColor White
Write-Host " Clean command: powershell ops/worktree_clean.ps1 -WorktreeName $WorktreeName" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
