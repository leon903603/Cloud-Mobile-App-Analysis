<#
.SYNOPSIS
    Cleans up a Git Worktree for Cloud-Mobile-App-Analysis and releases Git locks.

.DESCRIPTION
    Safely removes the worktree located at Cloud-Mobile-App-Analysis/.worktrees/<WorktreeName>,
    cleans up untracked artifacts (node_modules, SQLite files), prunes Git worktree metadata,
    and optionally deletes the local Git branch.

.PARAMETER WorktreeName
    The name of the worktree folder to remove.

.PARAMETER DeleteBranch
    If specified, deletes the associated local Git branch after worktree removal.

.PARAMETER Force
    Force removal even if there are uncommitted changes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$WorktreeName,

    [Parameter()]
    [switch]$DeleteBranch,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CandidateRoot = Resolve-Path (Join-Path $ScriptDir "..")

if (Test-Path (Join-Path $CandidateRoot "Cloud-Mobile-App-Analysis\.git")) {
    $RepoPath = (Join-Path $CandidateRoot "Cloud-Mobile-App-Analysis")
} elseif (Test-Path (Join-Path $CandidateRoot ".git")) {
    $RepoPath = $CandidateRoot.Path
} else {
    Write-Error "Target repository not found or not a Git repo at: $CandidateRoot"
    exit 1
}

$WorktreesRoot = Join-Path $RepoPath ".worktrees"
$TargetWorktreePath = Join-Path $WorktreesRoot $WorktreeName

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Cleaning CMAA Worktree: $WorktreeName" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Find current branch of the worktree before deleting
$AssociatedBranch = ""
try {
    $normalizedTargetPath = [System.IO.Path]::GetFullPath($TargetWorktreePath).TrimEnd("\", "/")
    $rawText = (git -C $RepoPath worktree list --porcelain) -join "`n"
    $blocks = $rawText -split "(?m)^\r?$"
    foreach ($block in $blocks) {
        $currentPath = ""
        $currentBranch = ""
        foreach ($line in ($block -split "`r?`n")) {
            if ($line -match "^worktree\s+(.*)$") {
                $currentPath = [System.IO.Path]::GetFullPath($matches[1].Trim()).TrimEnd("\", "/")
            } elseif ($line -match "^branch\s+refs/heads/(.*)$") {
                $currentBranch = $matches[1].Trim()
            }
        }
        if ($currentPath -and ($currentPath -eq $normalizedTargetPath)) {
            $AssociatedBranch = $currentBranch
            break
        }
    }
} catch {
    Write-Warning "Could not determine associated branch: $_"
}

# Remove worktree via Git
Write-Host "[*] Removing Git worktree registration..." -ForegroundColor Yellow
$forceFlag = if ($Force) { "--force" } else { "" }

if (Test-Path $TargetWorktreePath) {
    if ($forceFlag) {
        git -C $RepoPath worktree remove --force ".worktrees/$WorktreeName"
    } else {
        git -C $RepoPath worktree remove ".worktrees/$WorktreeName"
    }
}

# Prune git worktree metadata
Write-Host "[*] Pruning Git worktree metadata..." -ForegroundColor Yellow
git -C $RepoPath worktree prune

# If physical directory still exists (e.g. untracked node_modules or sqlite dbs), wipe it
if (Test-Path $TargetWorktreePath) {
    Write-Host "[*] Purging remaining untracked files ($TargetWorktreePath)..." -ForegroundColor Yellow
    Remove-Item -Path $TargetWorktreePath -Recurse -Force -ErrorAction SilentlyContinue
}

# Optionally delete local branch with safety guardrail against main/master
$ProtectedBranches = @("main", "master", "develop", "android-static", "pdf-generator")
if ($DeleteBranch -and -not [string]::IsNullOrWhiteSpace($AssociatedBranch)) {
    if ($ProtectedBranches -contains $AssociatedBranch) {
        Write-Warning "Safety Guardrail: Refusing to delete protected branch '$AssociatedBranch'!"
    } else {
        Write-Host "[*] Deleting local branch '$AssociatedBranch'..." -ForegroundColor Yellow
        git -C $RepoPath branch -D $AssociatedBranch
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Worktree Cleanup Complete!" -ForegroundColor Green
Write-Host " Active Worktrees:" -ForegroundColor White
git -C $RepoPath worktree list
Write-Host "==========================================================" -ForegroundColor Cyan
