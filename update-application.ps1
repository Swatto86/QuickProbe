<#
.SYNOPSIS
    QuickProbe Release Script - Creates versioned releases with proper Git tagging.

.DESCRIPTION
    This script automates the release process:
    1. Validates semantic version format (x.y.z)
    2. Updates version in Cargo.toml and tauri.conf.json
    3. Commits the version bump
    4. Creates an annotated Git tag with release notes
    5. Pushes commits and tag to origin

    The release notes flow: PowerShell -> Git tag annotation -> GitHub Release body -> Update UI

.PARAMETER Version
    The new version number in semantic version format (e.g., 1.2.3)

.PARAMETER Notes
    Release notes/changelog for this version. Can be multi-line.

.PARAMETER Force
    If specified, allows overwriting an existing version/tag. Will delete the existing tag
    locally and remotely before creating the new one.

.EXAMPLE
    .\update-application.ps1 -Version "1.2.0" -Notes "Added dark mode support"

.EXAMPLE
    .\update-application.ps1 -Version "1.2.0" -Notes "Fixed bug" -Force
    # Overwrites existing v1.2.0 release

.EXAMPLE
    .\update-application.ps1
    # Interactive mode - prompts for version and notes
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [string]$Notes,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Configuration (Tauri 2.x paths)
$CargoTomlPath = Join-Path $PSScriptRoot "src-tauri\Cargo.toml"
$TauriConfPath = Join-Path $PSScriptRoot "src-tauri\tauri.conf.json"
$AboutHtmlPath = Join-Path $PSScriptRoot "ui\about.html"

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Step {
    param([string]$Message)
    Write-ColorOutput "`n=> $Message" "Cyan"
}

function Write-SuccessMsg {
    param([string]$Message)
    Write-ColorOutput "[OK] $Message" "Green"
}

function Write-WarningMsg {
    param([string]$Message)
    Write-ColorOutput "[!] $Message" "Yellow"
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-ColorOutput "[X] $Message" "Red"
}

function Test-SemanticVersion {
    param([string]$Ver)
    return $Ver -match '^\d+\.\d+\.\d+$'
}

function Get-CurrentVersion {
    if (-not (Test-Path $CargoTomlPath)) {
        throw "Cargo.toml not found at: $CargoTomlPath"
    }
    
    $content = Get-Content $CargoTomlPath -Raw
    if ($content -match 'version\s*=\s*"(\d+\.\d+\.\d+)"') {
        return $matches[1]
    }
    throw "Could not parse version from Cargo.toml"
}

function Compare-Versions {
    param(
        [string]$New,
        [string]$Current
    )
    
    $newParts = $New -split '\.' | ForEach-Object { [int]$_ }
    $currentParts = $Current -split '\.' | ForEach-Object { [int]$_ }
    
    for ($i = 0; $i -lt 3; $i++) {
        if ($newParts[$i] -gt $currentParts[$i]) { return 1 }
        if ($newParts[$i] -lt $currentParts[$i]) { return -1 }
    }
    return 0
}

function Update-CargoToml {
    param([string]$NewVersion)
    
    $content = Get-Content $CargoTomlPath -Raw
    $pattern = '(version\s*=\s*")(\d+\.\d+\.\d+)(")'
    $replacement = "`${1}$NewVersion`${3}"
    $updated = $content -replace $pattern, $replacement
    
    Set-Content -Path $CargoTomlPath -Value $updated -NoNewline
}

function Update-TauriConf {
    param([string]$NewVersion)
    
    $json = Get-Content $TauriConfPath -Raw | ConvertFrom-Json
    # Tauri 2.x: version is at root level, not under 'package'
    $json.version = $NewVersion
    
    $jsonString = $json | ConvertTo-Json -Depth 10
    Set-Content -Path $TauriConfPath -Value $jsonString -NoNewline
}

function Update-AboutHtml {
    param([string]$NewVersion)
    
    $content = Get-Content $AboutHtmlPath -Raw
    # Update the default version shown in the About dialog
    $pattern = '(<span id="about-version" class="text-primary">)(\d+\.\d+\.\d+)(</span>)'
    $replacement = "`${1}$NewVersion`${3}"
    $updated = $content -replace $pattern, $replacement
    
    Set-Content -Path $AboutHtmlPath -Value $updated -NoNewline
}

function Test-GitClean {
    $status = git status --porcelain 2>$null
    return [string]::IsNullOrWhiteSpace($status)
}

function Test-GitTagExists {
    param([string]$Tag)
    $exists = git tag -l $Tag 2>$null
    return -not [string]::IsNullOrWhiteSpace($exists)
}

function Remove-OldTagsAndReleases {
    param([string]$NewTag)
    
    Write-Step "Cleaning up old tags and releases"
    
    # Get all local tags
    $allTags = git tag -l 2>$null | Where-Object { $_ -match '^v\d+\.\d+\.\d+$' }
    
    if ($allTags.Count -eq 0) {
        Write-ColorOutput "  No existing version tags found" "Gray"
        return
    }
    
    $tagsToDelete = $allTags | Where-Object { $_ -ne $NewTag }
    
    if ($tagsToDelete.Count -eq 0) {
        Write-ColorOutput "  No old tags to remove" "Gray"
        return
    }
    
    Write-ColorOutput "  Found $($tagsToDelete.Count) old tag(s) to remove" "White"
    
    foreach ($tag in $tagsToDelete) {
        Write-ColorOutput "  Removing tag: $tag" "Gray"
        
        # Delete GitHub release first (if gh CLI is available)
        $ghAvailable = Get-Command gh -ErrorAction SilentlyContinue
        if ($ghAvailable) {
            # Check if release exists and delete it
            $null = gh release view $tag 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "    Deleting GitHub release for $tag..." "Gray"
                gh release delete $tag --yes 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-ColorOutput "    Deleted GitHub release: $tag" "Green"
                }
                else {
                    Write-WarningMsg "    Failed to delete GitHub release: $tag (may not exist)"
                }
            }
        }
        else {
            Write-WarningMsg "    GitHub CLI (gh) not found - skipping release deletion for $tag"
            Write-ColorOutput "    Install gh: https://cli.github.com/" "Gray"
        }
        
        # Delete remote tag
        git push origin --delete $tag 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "    Deleted remote tag: $tag" "Green"
        }
        else {
            Write-ColorOutput "    Remote tag $tag may not exist or already deleted" "Gray"
        }
        
        # Delete local tag
        git tag -d $tag 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "    Deleted local tag: $tag" "Green"
        }
    }
    
    Write-SuccessMsg "Cleaned up $($tagsToDelete.Count) old tag(s) and their releases"
}

# ============================================================================
# Main Script
# ============================================================================

Write-ColorOutput "`n============================================================" "Cyan"
Write-ColorOutput "           QuickProbe Release Script                        " "Cyan"
Write-ColorOutput "============================================================" "Cyan"

# Get current version
try {
    $currentVersion = Get-CurrentVersion
    Write-ColorOutput "`nCurrent version: $currentVersion" "White"
}
catch {
    Write-ErrorMsg "Failed to read current version: $_"
    exit 1
}

# Prompt for version if not provided
if ([string]::IsNullOrWhiteSpace($Version)) {
    Write-Host ""
    $Version = Read-Host "Enter new version (current: $currentVersion)"
}

# Validate version format
if (-not (Test-SemanticVersion $Version)) {
    Write-ErrorMsg "Invalid version format. Must be semantic version (e.g., 1.2.3)"
    exit 1
}

# Check version is newer
$comparison = Compare-Versions -New $Version -Current $currentVersion
if ($comparison -eq 0 -and -not $Force) {
    Write-ErrorMsg "Version $Version is the same as current version. Use -Force to overwrite."
    exit 1
}
if ($comparison -lt 0 -and -not $Force) {
    Write-WarningMsg "Version $Version is older than current version ($currentVersion)"
    $confirm = Read-Host "Continue anyway? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-ColorOutput "Release cancelled" "Yellow"
        exit 0
    }
}

# Check if tag already exists
$tagName = "v$Version"
if (Test-GitTagExists $tagName) {
    if ($Force) {
        Write-WarningMsg "Tag $tagName exists. Deleting it (Force mode)..."
        
        # Delete local tag
        git tag -d $tagName 2>$null
        
        # Delete remote tag
        git push origin --delete $tagName 2>$null
        
        Write-SuccessMsg "Deleted existing tag $tagName"
    }
    else {
        Write-ErrorMsg "Tag $tagName already exists. Use -Force to overwrite, or choose a different version."
        exit 1
    }
}

# Prompt for release notes if not provided
if ([string]::IsNullOrWhiteSpace($Notes)) {
    Write-Host ""
    Write-ColorOutput "Enter release notes (press Enter twice when done):" "White"
    $noteLines = @()
    while ($true) {
        $line = Read-Host
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($noteLines.Count -eq 0) {
                Write-WarningMsg "Release notes cannot be empty"
                continue
            }
            break
        }
        $noteLines += $line
    }
    $Notes = $noteLines -join "`n"
}

# Show summary and confirm
Write-ColorOutput "`n============================================================" "Yellow"
Write-ColorOutput "                    Release Summary                         " "Yellow"
Write-ColorOutput "============================================================" "Yellow"
Write-ColorOutput "  Version:  $currentVersion -> $Version" "White"
Write-ColorOutput "  Tag:      $tagName" "White"
Write-ColorOutput "  Notes:" "White"
$Notes -split "`n" | ForEach-Object { Write-ColorOutput "            $_" "Gray" }
Write-Host ""

$confirm = Read-Host "Proceed with release? (y/N)"
if ($confirm -ne 'y' -and $confirm -ne 'Y') {
    Write-ColorOutput "Release cancelled" "Yellow"
    exit 0
}

# Check for uncommitted changes
Write-Step "Checking Git status"
if (-not (Test-GitClean)) {
    Write-WarningMsg "You have uncommitted changes. They will be included in the version bump commit."
    $confirm = Read-Host "Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        exit 0
    }
}

# Remove old tags and releases before creating the new one
Remove-OldTagsAndReleases -NewTag $tagName

# Update version files
Write-Step "Updating Cargo.toml"
try {
    Update-CargoToml -NewVersion $Version
    Write-SuccessMsg "Updated Cargo.toml to version $Version"
}
catch {
    Write-ErrorMsg "Failed to update Cargo.toml: $_"
    exit 1
}

Write-Step "Updating tauri.conf.json"
try {
    Update-TauriConf -NewVersion $Version
    Write-SuccessMsg "Updated tauri.conf.json to version $Version"
}
catch {
    Write-ErrorMsg "Failed to update tauri.conf.json: $_"
    # Attempt to restore Cargo.toml
    git checkout -- $CargoTomlPath 2>$null
    exit 1
}

Write-Step "Updating about.html"
try {
    Update-AboutHtml -NewVersion $Version
    Write-SuccessMsg "Updated about.html to version $Version"
}
catch {
    Write-ErrorMsg "Failed to update about.html: $_"
    # Attempt to restore previous files
    git checkout -- $CargoTomlPath $TauriConfPath 2>$null
    exit 1
}

# Git operations
Write-Step "Staging version changes"
git add $CargoTomlPath $TauriConfPath $AboutHtmlPath
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to stage changes"
    exit 1
}

Write-Step "Committing version bump"
$commitMessage = "chore: bump version to $Version"
# Use --allow-empty for Force mode (re-releasing same version)
if ($Force) {
    git commit --allow-empty -m $commitMessage
}
else {
    git commit -m $commitMessage
}
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to commit changes"
    exit 1
}
Write-SuccessMsg "Created commit: $commitMessage"

Write-Step "Creating annotated tag $tagName"
# Create annotated tag with release notes as the message
git tag -a $tagName -m $Notes
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to create tag"
    # Attempt to undo commit
    git reset --soft HEAD~1
    exit 1
}
Write-SuccessMsg "Created tag $tagName with release notes"

Write-Step "Pushing commits to origin"
git push origin
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to push commits"
    Write-WarningMsg "You may need to push manually: git push origin"
}
else {
    Write-SuccessMsg "Pushed commits to origin"
}

Write-Step "Pushing tag to origin"
git push origin $tagName
if ($LASTEXITCODE -ne 0) {
    Write-ErrorMsg "Failed to push tag"
    Write-WarningMsg "You may need to push manually: git push origin $tagName"
}
else {
    Write-SuccessMsg "Pushed tag $tagName to origin"
}

# Final summary
Write-ColorOutput "`n============================================================" "Green"
Write-ColorOutput "                   Release Complete!                        " "Green"
Write-ColorOutput "============================================================" "Green"
Write-ColorOutput "`n  Version $Version has been released." "White"
Write-ColorOutput "  GitHub Actions will now build and publish the release." "White"
Write-ColorOutput "`n  Monitor the build at:" "White"
Write-ColorOutput "  https://github.com/Swatto86/QuickProbe/actions" "Cyan"
Write-Host ""
