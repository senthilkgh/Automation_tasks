# rhsa-report.ps1
# Fetch RHSA data from Red Hat Security API for x86_64 RHEL systems

param(
    [Parameter(Mandatory=$false)]
    [string[]]$RHSAIds,

    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
)

# Function to fetch RHSA data
function Get-RHSAData {
    param([string]$RHSAID)

    try {
        Write-Host "Fetching data for: $RHSAID" -ForegroundColor Cyan

        $url = "https://access.redhat.com/hydra/rest/securitydata/cve.json?advisory=$RHSAID"
        $response = Invoke-RestMethod -Uri $url -Method Get -ContentType "application/json"

        $rhsaData = [PSCustomObject]@{
            RHSAID = $RHSAID
            CreatedDate = ""
            UpdatedDate = ""
            PackagesImpacted = ""
            FixedDate = ""
        }

        # Parse dates and convert to dd-MM-yyyy format
        if ($response.public_date) {
            $rhsaData.CreatedDate = (Get-Date $response.public_date -Format "dd-MM-yyyy")
        }

        if ($response.modified_date) {
            $rhsaData.UpdatedDate = (Get-Date $response.modified_date -Format "dd-MM-yyyy")
        }

        # Get affected packages for RHEL x86_64
        $packages = @()
        if ($response.affected_release) {
            foreach ($release in $response.affected_release) {
                if ($release.product_name -match "Red Hat Enterprise Linux" -and 
                    $release.architecture -eq "x86_64") {
                    $packages += $release.package
                }
            }
        }
        $rhsaData.PackagesImpacted = ($packages -join "; ")

        # Get fixed date
        if ($response.package_state) {
            $fixDates = $response.package_state | Where-Object { $_.fix_state -eq "Fixed" } | 
                        Select-Object -ExpandProperty fix_date -ErrorAction SilentlyContinue
            if ($fixDates) {
                $rhsaData.FixedDate = (Get-Date $fixDates[0] -Format "dd-MM-yyyy")
            }
        }

        if (-not $rhsaData.FixedDate -and $response.public_date) {
            $rhsaData.FixedDate = $rhsaData.CreatedDate
        }

        return $rhsaData

    } catch {
        Write-Host "Error fetching $RHSAID : $_" -ForegroundColor Red
        return $null
    }
}

# Main execution
Write-Host "`n=== RHSA Security Data Collector ===" -ForegroundColor Green
Write-Host "Target: Red Hat Enterprise Linux x86_64`n" -ForegroundColor Green

# Determine RHSA IDs to process
if ($InputFile) {
    if (Test-Path $InputFile) {
        $RHSAIds = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" }
        Write-Host "Reading from file: $InputFile" -ForegroundColor Yellow
    } else {
        Write-Host "Error: File not found - $InputFile" -ForegroundColor Red
        exit 1
    }
} elseif (-not $RHSAIds) {
    Write-Host "No RHSA IDs provided. Using sample list..." -ForegroundColor Yellow
    $RHSAIds = @("RHSA-2024:0001", "RHSA-2024:0002", "RHSA-2023:7549")
}

# Collect data
$results = @()
$total = $RHSAIds.Count
$current = 0

foreach ($rhsaId in $RHSAIds) {
    $current++
    Write-Progress -Activity "Fetching RHSA Data" -Status "Processing $rhsaId ($current of $total)" -PercentComplete (($current / $total) * 100)

    $data = Get-RHSAData -RHSAID $rhsaId
    if ($data) {
        $results += $data
    }
    Start-Sleep -Milliseconds 500
}

Write-Progress -Activity "Fetching RHSA Data" -Completed

# Export to CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport generated successfully!" -ForegroundColor Green
    Write-Host "Location: $OutputPath" -ForegroundColor Cyan
    Write-Host "Total records: $($results.Count)`n" -ForegroundColor Cyan

    # Display preview
    Write-Host "Preview:" -ForegroundColor Yellow
    $results | Format-Table -AutoSize
} else {
    Write-Host "`nNo data collected." -ForegroundColor Red
}
