# rhsa-scraper.ps1
# Complete RHSA data scraper for Red Hat Security Advisories
# Version: 1.0

param(
    [Parameter(Mandatory=$false)]
    [string[]]$RHSAIds,

    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
)

function Get-RHSADataFromWeb {
    param([string]$RHSAID)

    try {
        Write-Host "Fetching: $RHSAID" -ForegroundColor Cyan

        $url = "https://access.redhat.com/errata/$RHSAID"
        $headers = @{'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        $response = Invoke-WebRequest -Uri $url -Headers $headers -TimeoutSec 30
        $html = $response.Content

        $result = [PSCustomObject]@{
            RHSAID = $RHSAID
            CreatedDate = "N/A"
            UpdatedDate = "N/A"
            PackagesImpacted = "N/A"
            FixedDate = "N/A"
        }

        # Extract Issued date
        if ($html -match 'Issued:\s*(\d{4}-\d{2}-\d{2})') {
            $result.CreatedDate = (Get-Date $matches[1] -Format "dd-MM-yyyy")
            $result.FixedDate = $result.CreatedDate
            Write-Host "  Issued: $($matches[1])" -ForegroundColor Gray
        } elseif ($html -match 'datePublished["\s:]+(\d{4}-\d{2}-\d{2})') {
            $result.CreatedDate = (Get-Date $matches[1] -Format "dd-MM-yyyy")
            $result.FixedDate = $result.CreatedDate
            Write-Host "  Issued: $($matches[1])" -ForegroundColor Gray
        }

        # Extract Updated date
        if ($html -match 'Updated:\s*(\d{4}-\d{2}-\d{2})') {
            $result.UpdatedDate = (Get-Date $matches[1] -Format "dd-MM-yyyy")
            Write-Host "  Updated: $($matches[1])" -ForegroundColor Gray
        } elseif ($html -match 'dateModified["\s:]+(\d{4}-\d{2}-\d{2})') {
            $result.UpdatedDate = (Get-Date $matches[1] -Format "dd-MM-yyyy")
            Write-Host "  Updated: $($matches[1])" -ForegroundColor Gray
        }

        # Fallback: get all dates
        if ($result.CreatedDate -eq "N/A" -or $result.UpdatedDate -eq "N/A") {
            $allDates = [regex]::Matches($html, '\b(\d{4})-(\d{2})-(\d{2})\b') | 
                        ForEach-Object { $_.Value } | 
                        Where-Object { $year = [int]$_.Substring(0,4); $year -ge 2020 -and $year -le 2030 } | 
                        Select-Object -Unique

            if ($allDates.Count -ge 1 -and $result.CreatedDate -eq "N/A") {
                $result.CreatedDate = (Get-Date $allDates[0] -Format "dd-MM-yyyy")
                $result.FixedDate = $result.CreatedDate
            }
            if ($allDates.Count -ge 2 -and $result.UpdatedDate -eq "N/A") {
                $result.UpdatedDate = (Get-Date $allDates[1] -Format "dd-MM-yyyy")
            }
        }

        if ($result.UpdatedDate -eq "N/A" -and $result.CreatedDate -ne "N/A") {
            $result.UpdatedDate = $result.CreatedDate
        }

        # Extract packages
        $packages = @()
        $packagePatterns = @(
            '([\w\-\.]+)-(\d+[\w\.\-]+)\.(x86_64|noarch)\.rpm',
            '>([\w\-\.]+)-(\d+[\w\.\-]+)\.(x86_64|noarch)<',
            '([\w\-]+)-(\d[\w\.\-]+)\.el\d+[^\s]*\.(x86_64|noarch)'
        )

        foreach ($pattern in $packagePatterns) {
            $matches = [regex]::Matches($html, $pattern)
            foreach ($match in $matches) {
                if ($match.Groups.Count -ge 4) {
                    $pkgName = "$($match.Groups[1].Value)-$($match.Groups[2].Value).$($match.Groups[3].Value)"
                    if ($packages -notcontains $pkgName -and $pkgName -notmatch 'src\.rpm') {
                        $packages += $pkgName
                    }
                }
            }
            if ($packages.Count -gt 0) { break }
        }

        if ($packages.Count -gt 0) {
            $uniquePackages = $packages | Select-Object -Unique | Sort-Object | Select-Object -First 50
            $result.PackagesImpacted = $uniquePackages -join "; "
            Write-Host "  Packages: $($uniquePackages.Count)" -ForegroundColor Gray
        }

        Write-Host "  Success!" -ForegroundColor Green
        return $result

    } catch {
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  RHSA Security Data Scraper" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

if ($InputFile) {
    if (Test-Path $InputFile) {
        $RHSAIds = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^#" } | ForEach-Object { $_.Trim() }
        Write-Host "Input: $InputFile" -ForegroundColor Yellow
        Write-Host "Total: $($RHSAIds.Count) RHSAs" -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "ERROR: File not found - $InputFile" -ForegroundColor Red
        exit 1
    }
} elseif ($RHSAIds) {
    Write-Host "Processing: $($RHSAIds.Count) RHSA(s)" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "ERROR: No RHSA IDs provided!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\rhsa-scraper.ps1 -RHSAIds 'RHSA-2025:23382'" -ForegroundColor Cyan
    Write-Host "  .\rhsa-scraper.ps1 -RHSAIds 'RHSA-2025:23382','RHSA-2024:0001'" -ForegroundColor Cyan
    Write-Host "  .\rhsa-scraper.ps1 -InputFile 'rhsa-list.txt'" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

$outputDir = Split-Path -Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    try {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    } catch {
        $OutputPath = Split-Path -Path $OutputPath -Leaf
    }
}

$results = @()
$total = $RHSAIds.Count
$successful = 0
$failed = 0

for ($i = 0; $i -lt $total; $i++) {
    $current = $i + 1
    Write-Host "[$current/$total]" -ForegroundColor Cyan

    $data = Get-RHSADataFromWeb -RHSAID $RHSAIds[$i].Trim()

    if ($data) {
        $results += $data
        $successful++
    } else {
        $failed++
    }

    Write-Host ""
    if ($current -lt $total) { Start-Sleep -Seconds 2 }
}

Write-Host "========================================" -ForegroundColor Green

if ($results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        $fullPath = (Resolve-Path $OutputPath).Path

        Write-Host "SUCCESS: Report Generated!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "File: $OutputPath" -ForegroundColor Cyan
        Write-Host "Path: $fullPath" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Statistics:" -ForegroundColor Yellow
        Write-Host "  Total: $total" -ForegroundColor White
        Write-Host "  Success: $successful" -ForegroundColor Green
        Write-Host "  Failed: $failed" -ForegroundColor Red
        Write-Host ""
        Write-Host "Data Preview:" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""

        $results | Format-Table -Property RHSAID, CreatedDate, UpdatedDate, FixedDate -AutoSize

        Write-Host ""
        if ($results[0].PackagesImpacted -ne "N/A") {
            Write-Host "Sample Packages:" -ForegroundColor Yellow
            $pkgs = $results[0].PackagesImpacted -split "; " | Select-Object -First 5
            foreach ($pkg in $pkgs) { Write-Host "  - $pkg" }
            Write-Host ""
        }

        $openFile = Read-Host "Open CSV? (Y/N)"
        if ($openFile -eq "Y" -or $openFile -eq "y") { Start-Process $OutputPath }

    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $fallbackPath = "RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"
        $results | Export-Csv -Path $fallbackPath -NoTypeInformation -Encoding UTF8
        Write-Host "Saved to: $fallbackPath" -ForegroundColor Green
        Start-Process $fallbackPath
    }
} else {
    Write-Host "ERROR: No data collected!" -ForegroundColor Red
}

Write-Host ""
Write-Host "Completed!" -ForegroundColor Green
Write-Host ""
