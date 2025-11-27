[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$WebhookUrl = "WEBHOOK_HERE_FOR_DATA",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("json", "csv")]
    [string]$OutputFormat = "json"
)

# Color configuration
$script:OriginalForegroundColor = $Host.UI.RawUI.ForegroundColor

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    $Host.UI.RawUI.ForegroundColor = $Color
    if ($NoNewline) {
        Write-Host $Message -NoNewline
    } else {
        Write-Host $Message
    }
    $Host.UI.RawUI.ForegroundColor = $script:OriginalForegroundColor
}

function Test-NpmInstalled {
    try {
        $null = npm --version 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

function Get-InstalledNpmPackages {
    param(
        [string]$Scope = "global"
    )
    
    try {
        $scopeFlag = if ($Scope -eq "global") { "-g" } else { "" }
        $output = npm list $scopeFlag --depth=0 --json 2>$null | ConvertFrom-Json
        
        $packages = @()
        if ($output.dependencies) {
            foreach ($pkg in $output.dependencies.PSObject.Properties) {
                $packages += [PSCustomObject]@{
                    Name = $pkg.Name
                    Version = $pkg.Value.version
                    Scope = $Scope
                }
            }
        }
        return $packages
    } catch {
        Write-ColorOutput "Warning: Could not retrieve $Scope npm packages. Error: $_" -Color "Yellow"
        return @()
    }
}

function Send-WebhookData {
    param(
        [array]$Data,
        [string]$Url,
        [string]$Format,
        [hashtable]$Metadata
    )
    
    try {
        $payload = @{
            timestamp = (Get-Date).ToString("o")
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            totalPackagesChecked = $Metadata.TotalChecked
            impactedPackagesFound = $Metadata.FoundCount
            packagesNotFound = $Metadata.NotFoundCount
            format = $Format
            packages = $Data
        }
        
        if ($Format -eq "json") {
            $body = $payload | ConvertTo-Json -Depth 10
            $contentType = "application/json"
        } else {
            # For CSV, convert to CSV string and include in payload
            if ($Data.Count -gt 0) {
                # Convert to PSCustomObject array for CSV export
                $csvData = $Data | Select-Object PackageName, Version, Scope, Status, DetectedAt, Hostname, Username | ConvertTo-Csv -NoTypeInformation | Out-String
                $payload.packages = $csvData
            }
            $body = $payload | ConvertTo-Json -Depth 10
            $contentType = "application/json"
        }
        
        Write-ColorOutput "`nSending data to webhook..." -Color "Cyan"
        
        $response = Invoke-RestMethod -Uri $Url -Method Post -Body $body -ContentType $contentType -ErrorAction Stop
        
        Write-ColorOutput "Successfully sent data to webhook!" -Color "Green"
        return $true
    } catch {
        Write-ColorOutput "ERROR: Failed to send data to webhook" -Color "Red"
        Write-ColorOutput "Error details: $($_.Exception.Message)" -Color "Red"
        
        # Save locally as backup
        $backupFile = ".\webhook_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').$Format"
        if ($Format -eq "json") {
            $payload | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile
        } else {
            $Data | Export-Csv -Path $backupFile -NoTypeInformation
        }
        Write-ColorOutput "Data saved locally to: $backupFile" -Color "Yellow"
        return $false
    }
}

# Main script execution
# *** MODIFICATION: Updated to use the new package list file name ***
$PackageListPath = ".\impacted_packages_with_versions.txt"

Write-ColorOutput "`n========================================" -Color "Cyan"
Write-ColorOutput "  NPM Package Security Checker" -Color "Cyan"
Write-ColorOutput "========================================`n" -Color "Cyan"

# Validate npm is installed
if (-not (Test-NpmInstalled)) {
    Write-ColorOutput "ERROR: npm is not installed or not in PATH" -Color "Red"
    Write-ColorOutput "Please install Node.js and npm before running this script.`n" -Color "Yellow"
    exit 1
}

# Validate input file exists
if (-not (Test-Path -Path $PackageListPath)) {
    Write-ColorOutput "ERROR: Package list file not found: $PackageListPath" -Color "Red"
    exit 1
}

# Read impacted packages (now in package@version format)
Write-ColorOutput "Reading impacted packages from: $PackageListPath" -Color "White"
$impactedPackagesWithVersion = Get-Content -Path $PackageListPath | Where-Object { $_.Trim() -ne "" }

if ($impactedPackagesWithVersion.Count -eq 0) {
    Write-ColorOutput "Warning: No packages found in the input file.`n" -Color "Yellow"
    exit 0
}

Write-ColorOutput "Found $($impactedPackagesWithVersion.Count) package(s) to check`n" -Color "White"

# Get installed packages (both global and local)
Write-ColorOutput "Retrieving globally installed npm packages..." -Color "White"
$globalPackages = Get-InstalledNpmPackages -Scope "global"

Write-ColorOutput "Retrieving locally installed npm packages..." -Color "White"
$localPackages = Get-InstalledNpmPackages -Scope "local"

$allInstalledPackages = @($globalPackages) + @($localPackages)

if ($allInstalledPackages.Count -eq 0) {
    Write-ColorOutput "Warning: No npm packages found installed on this system.`n" -Color "Yellow"
    exit 0
}

Write-ColorOutput "Total installed packages: $($allInstalledPackages.Count) (Global: $($globalPackages.Count), Local: $($localPackages.Count))`n" -Color "White"

# Check for impacted packages
Write-ColorOutput "Checking for impacted packages...`n" -Color "Cyan"

$foundPackages = @()
$notFoundCount = 0

foreach ($packageWithVersion in $impactedPackagesWithVersion) {
    $packageWithVersion = $packageWithVersion.Trim()
    
    if ([string]::IsNullOrWhiteSpace($packageWithVersion)) {
        continue
    }
    
    # Split package@version into package_name and required_version
    # This logic is robust for scoped packages as it splits on the last '@'
    $parts = $packageWithVersion -split '@'
    $requiredVersion = $parts[-1]
    
    # Package name is everything before the last '@'
    $packageName = $packageWithVersion.Substring(0, $packageWithVersion.Length - $requiredVersion.Length - 1)
    
    # *** FIX: Ensure the full package@version string is displayed ***
    Write-ColorOutput "  Checking: " -Color "Gray" -NoNewline
    Write-ColorOutput "$packageWithVersion" -Color "White" -NoNewline
    
    # Filter by both Name AND Version
    $matchedPackages = $allInstalledPackages | Where-Object { 
        $_.Name -eq $packageName -and $_.Version -eq $requiredVersion 
    }
    
    if ($matchedPackages) {
        Write-ColorOutput " [FOUND]" -Color "Red"
        
        foreach ($match in $matchedPackages) {
            $foundPackages += [PSCustomObject]@{
                PackageName = $match.Name
                Version = $match.Version
                Scope = $match.Scope
                Status = "Vulnerable"
                DetectedAt = (Get-Date).ToString("o")
                Hostname = $env:COMPUTERNAME
                Username = $env:USERNAME
            }
        }
    } else {
        Write-ColorOutput " [Not Found]" -Color "Green"
        $notFoundCount++
    }
}

# Prepare metadata
$metadata = @{
    TotalChecked = $impactedPackagesWithVersion.Count
    FoundCount = $foundPackages.Count
    NotFoundCount = $notFoundCount
}

# Summary
Write-ColorOutput "`n========================================" -Color "Cyan"
Write-ColorOutput "  Summary" -Color "Cyan"
Write-ColorOutput "========================================" -Color "Cyan"
Write-ColorOutput "Total packages checked: $($metadata.TotalChecked)" -Color "White"
Write-ColorOutput "Impacted packages found: $($metadata.FoundCount)" -Color $(if ($metadata.FoundCount -gt 0) { "Red" } else { "Green" })
Write-ColorOutput "Packages not found: $($metadata.NotFoundCount)" -Color "Green"

# Display found packages
if ($foundPackages.Count -gt 0) {
    Write-ColorOutput "`nIMPACTED PACKAGES DETECTED:" -Color "Red"
    foreach ($pkg in $foundPackages) {
        Write-ColorOutput "  - $($pkg.PackageName) v$($pkg.Version) [$($pkg.Scope)]" -Color "Yellow"
    }
    
    Write-ColorOutput "`nACTION REQUIRED: Please update or remove the impacted packages.`n" -Color "Red"
} else {
    Write-ColorOutput "`nGood news! No impacted packages found on this system.`n" -Color "Green"
}

# Send data to webhook
$webhookSuccess = Send-WebhookData -Data $foundPackages -Url $WebhookUrl -Format $OutputFormat -Metadata $metadata

if ($webhookSuccess) {
    Write-ColorOutput "`nData successfully transmitted to monitoring system." -Color "Green"
} else {
    Write-ColorOutput "`nWarning: Data transmission failed but results are saved locally." -Color "Yellow"
}

Write-ColorOutput "`nScript execution completed.`n" -Color "Cyan"

# Exit with appropriate code
if ($foundPackages.Count -gt 0) {
    exit 1
} else {
    exit 0
}
