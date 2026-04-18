# rhsa-scraper.ps1
# Scrape RHSA data from Red Hat website for x86_64 RHEL systems

param(
    [Parameter(Mandatory=$false)]
    [string[]]$RHSAIds,

    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
)

# Function to scrape RHSA page
function Get-RHSADataFromWeb {
    param([string]$RHSAID)

    try {
        Write-Host "Fetching data for: $RHSAID" -ForegroundColor Cyan

        $url = "https://access.redhat.com/errata/$RHSAID"
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30

        if ($response.StatusCode -ne 200) {
            Write-Host "  Error: Unable to fetch $RHSAID" -ForegroundColor Red
            return $null
        }

        $content = $response.Content

        # Initialize result object
        $rhsaData = [PSCustomObject]@{
            RHSAID = $RHSAID
            CreatedDate = "N/A"
            UpdatedDate = "N/A"
            PackagesImpacted = "N/A"
            FixedDate = "N/A"
        }

        # Extract Issue Date - Pattern: Issued:2025-12-16
        if ($content -match 'Issued:(\d{4}-\d{2}-\d{2})') {
            $dateStr = $matches[1]
            try {
                $rhsaData.CreatedDate = (Get-Date $dateStr -Format "dd-MM-yyyy")
                $rhsaData.FixedDate = $rhsaData.CreatedDate
            } catch {
                $rhsaData.CreatedDate = $dateStr
            }
        }

        # Extract Updated Date - Pattern: Updated:2025-12-18
        if ($content -match 'Updated:(\d{4}-\d{2}-\d{2})') {
            $dateStr = $matches[1]
            try {
                $rhsaData.UpdatedDate = (Get-Date $dateStr -Format "dd-MM-yyyy")
            } catch {
                $rhsaData.UpdatedDate = $dateStr
            }
        }

        # If no updated date found, use created date
        if ($rhsaData.UpdatedDate -eq "N/A" -and $rhsaData.CreatedDate -ne "N/A") {
            $rhsaData.UpdatedDate = $rhsaData.CreatedDate
        }

        # Extract packages for x86_64 and noarch
        $packages = @()

        # Pattern 1: Package names with version and architecture
        $packagePattern1 = '([a-zA-Z0-9_\-\.]+)-(\d+[\.\-\w]*)\.(x86_64|noarch)\.rpm'
        $packageMatches = [regex]::Matches($content, $packagePattern1)

        foreach ($match in $packageMatches) {
            $packageName = "$($match.Groups[1].Value)-$($match.Groups[2].Value).$($match.Groups[3].Value)"
            if ($packages -notcontains $packageName) {
                $packages += $packageName
            }
        }

        # Pattern 2: Simple package names
        if ($packages.Count -eq 0) {
            $packagePattern2 = '([a-zA-Z0-9_\-]+)-(\d+[\.\-\w]+)\.el\d+[^\s]*\.(x86_64|noarch)'
            $packageMatches = [regex]::Matches($content, $packagePattern2)

            foreach ($match in $packageMatches) {
                $packageName = $match.Value
                if ($packages -notcontains $packageName) {
                    $packages += $packageName
                }
            }
        }

        if ($packages.Count -gt 0) {
            $rhsaData.PackagesImpacted = ($packages | Select-Object -Unique | Sort-Object) -join "; "
        }

        Write-Host "  Successfully fetched $RHSAID" -ForegroundColor Green
        Write-Host "    Issued: $($rhsaData.CreatedDate)" -ForegroundColor Gray
        Write-Host "    Updated: $($rhsaData.UpdatedDate)" -ForegroundColor Gray
        Write-Host "    Packages: $($packages.Count) found" -ForegroundColor Gray

        return $rhsaData

    } catch {
        Write-Host "  Error fetching $RHSAID : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Main execution
Write-Host ""
Write-Host "========================================"
Write-Host "  RHSA Security Data Scraper"
Write-Host "  Target: RHEL x86_64"
Write-Host "========================================"
Write-Host ""

# Determine RHSA IDs to process
if ($InputFile) {
    if (Test-Path $InputFile) {
        $RHSAIds = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^#" }
        Write-Host "Reading from file: $InputFile" -ForegroundColor Yellow
        Write-Host "Total RHSAs to process: $($RHSAIds.Count)" -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "Error: File not found - $InputFile" -ForegroundColor Red
        exit 1
    }
} elseif (-not $RHSAIds) {
    Write-Host "Error: No RHSA IDs provided!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\rhsa-scraper.ps1 -RHSAIds 'RHSA-2025:23382'" -ForegroundColor Cyan
    Write-Host "  .\rhsa-scraper.ps1 -RHSAIds 'RHSA-2025:23382','RHSA-2024:0001'" -ForegroundColor Cyan
    Write-Host "  .\rhsa-scraper.ps1 -InputFile 'rhsa-list.txt'" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# Ensure output directory exists
$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path -Path $outputDir)) {
    try {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        Write-Host "Created output directory: $outputDir" -ForegroundColor Yellow
        Write-Host ""
    } catch {
        Write-Host "Error: Cannot create output directory - $outputDir" -ForegroundColor Red
        Write-Host "Using current directory instead" -ForegroundColor Yellow
        $OutputPath = Split-Path -Path $OutputPath -Leaf
        Write-Host ""
    }
}

# Collect data
$results = @()
$total = $RHSAIds.Count
$current = 0
$successful = 0
$failed = 0

foreach ($rhsaId in $RHSAIds) {
    $current++
    Write-Host "[$current/$total] Processing..." -ForegroundColor Cyan

    $data = Get-RHSADataFromWeb -RHSAID $rhsaId.Trim()

    if ($data) {
        $results += $data
        $successful++
    } else {
        $failed++
    }

    Write-Host ""
    Start-Sleep -Seconds 2
}

# Export to CSV
Write-Host "========================================"

if ($results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

        Write-Host "Report generated successfully!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Location: $OutputPath" -ForegroundColor Cyan
        Write-Host "Full Path: $((Get-Item $OutputPath).FullName)" -ForegroundColor Cyan
        Write-Host "Total processed: $total" -ForegroundColor Cyan
        Write-Host "Successful: $successful" -ForegroundColor Green
        Write-Host "Failed: $failed" -ForegroundColor Red
        Write-Host ""
        Write-Host "Preview of collected data:" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""

        $results | Format-Table -AutoSize -Wrap

        Write-Host ""
        Write-Host "Opening CSV file..." -ForegroundColor Yellow
        Start-Process $OutputPath

    } catch {
        Write-Host "Error exporting to CSV: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempting to save to current directory..." -ForegroundColor Yellow

        $fallbackPath = "RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
        $results | Export-Csv -Path $fallbackPath -NoTypeInformation -Encoding UTF8

        Write-Host "Report saved to: $fallbackPath" -ForegroundColor Green
        Start-Process $fallbackPath
    }

} else {
    Write-Host "No data collected!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

Write-Host ""
Write-Host "Process completed!" -ForegroundColor Green
Write-Host ""