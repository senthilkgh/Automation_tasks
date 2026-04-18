#Requires -Version 5.1
<#
.SYNOPSIS
    RHSA Vulnerability Tracker Script
.DESCRIPTION
    Extracts RHSA IDs from rhsa_list.txt, fetches security data from Red Hat Errata page,
    and generates a CSV report with patching status based on fix dates.
.NOTES
    Author: Security Automation Script
    Version: 2.0
#>

# ============================================
# CONFIGURATION
# ============================================
$InputFile = "rhsa_list.txt"
$OutputFile = "rhsa_vulnerability_report.csv"
$RedHatErrataBaseURL = "https://access.redhat.com/errata"

# ============================================
# FUNCTIONS
# ============================================

function Get-PatchingStatus {
    param (
        [Parameter(Mandatory=$false)]
        [string]$FixedDate
    )

    try {
        # Check if FixedDate is empty or null
        if ([string]::IsNullOrWhiteSpace($FixedDate)) {
            return "not redhat product to fix"
        }

        # Parse the date
        $parsedDate = $null
        $dateFormats = @(
            "yyyy-MM-dd",
            "MM/dd/yyyy",
            "dd/MM/yyyy",
            "yyyy/MM/dd",
            "dd-MM-yyyy",
            "MM-dd-yyyy",
            "MMMM d, yyyy",
            "MMMM dd, yyyy",
            "MMM d, yyyy",
            "MMM dd, yyyy",
            "d MMMM yyyy",
            "dd MMMM yyyy",
            "yyyy-MM-ddTHH:mm:ss",
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        foreach ($format in $dateFormats) {
            if ([DateTime]::TryParseExact($FixedDate.Trim(), $format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
                break
            }
        }

        # If still not parsed, try general parsing
        if ($null -eq $parsedDate) {
            if (-not [DateTime]::TryParse($FixedDate, [ref]$parsedDate)) {
                return "not redhat product to fix"
            }
        }

        # Calculate 16th of last month
        $today = Get-Date
        $lastMonth = $today.AddMonths(-1)
        $sixteenthOfLastMonth = Get-Date -Year $lastMonth.Year -Month $lastMonth.Month -Day 16 -Hour 0 -Minute 0 -Second 0

        # Compare dates and return status
        if ($parsedDate -lt $sixteenthOfLastMonth) {
            return "vulnerability fixed on this month"
        }
        else {
            return "vulnerability will be fixed on next month patching."
        }
    }
    catch {
        Write-Warning "Error processing date '$FixedDate': $_"
        return "not redhat product to fix"
    }
}

function Get-RHSADataFromErrata {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RHSAID
    )

    $result = [PSCustomObject]@{
        RHSA_ID           = $RHSAID
        Synopsis          = ""
        Advisory_Type     = ""
        Severity          = ""
        Issued_Date       = ""
        Fixed_Date        = ""
        Updated_Date      = ""
        CVEs              = ""
        Affected_Products = ""
        Description       = ""
        Patching_Status   = ""
        Errata_URL        = ""
        Fetch_Status      = ""
    }

    try {
        # Build Errata URL
        $errataURL = "$RedHatErrataBaseURL/$RHSAID"
        $result.Errata_URL = $errataURL

        Write-Host "Fetching data for $RHSAID from $errataURL ..." -ForegroundColor Cyan

        # Set TLS 1.2 for secure connection
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Define headers to mimic browser request
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            "Accept-Language" = "en-US,en;q=0.5"
        }

        # Make web request with timeout
        $response = Invoke-WebRequest -Uri $errataURL -Method Get -Headers $headers -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            $htmlContent = $response.Content

            # Extract Synopsis/Title
            $synopsisMatch = [regex]::Match($htmlContent, '<h1[^>]*id="synopsis"[^>]*>([^<]+)</h1>')
            if (-not $synopsisMatch.Success) {
                $synopsisMatch = [regex]::Match($htmlContent, '<h1[^>]*>([^<]*RHSA[^<]*)</h1>')
            }
            if (-not $synopsisMatch.Success) {
                $synopsisMatch = [regex]::Match($htmlContent, '<title>([^<]+)</title>')
            }
            if ($synopsisMatch.Success) {
                $result.Synopsis = $synopsisMatch.Groups[1].Value.Trim() -replace '\s+', ' '
            }

            # Extract Advisory Type
            $typeMatch = [regex]::Match($htmlContent, 'Advisory Type[:\s]*</[^>]+>\s*<[^>]+>([^<]+)<')
            if (-not $typeMatch.Success) {
                $typeMatch = [regex]::Match($htmlContent, 'Type[:\s]*</th>\s*<td[^>]*>([^<]+)<')
            }
            if ($typeMatch.Success) {
                $result.Advisory_Type = $typeMatch.Groups[1].Value.Trim()
            }

            # Extract Severity
            $severityMatch = [regex]::Match($htmlContent, 'Severity[:\s]*</[^>]+>\s*<[^>]+[^>]*>([^<]+)<')
            if (-not $severityMatch.Success) {
                $severityMatch = [regex]::Match($htmlContent, 'severity["\s][^>]*>([^<]+)<')
            }
            if (-not $severityMatch.Success) {
                $severityMatch = [regex]::Match($htmlContent, '(Critical|Important|Moderate|Low)\s*security', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if ($severityMatch.Success) {
                $result.Severity = $severityMatch.Groups[1].Value.Trim()
            }

            # Extract Issued Date
            $issuedMatch = [regex]::Match($htmlContent, 'Issued[:\s]*</[^>]+>\s*<[^>]+>([^<]+)<')
            if (-not $issuedMatch.Success) {
                $issuedMatch = [regex]::Match($htmlContent, 'Issued[:\s]*([A-Za-z]+\s+\d{1,2},?\s+\d{4})')
            }
            if (-not $issuedMatch.Success) {
                $issuedMatch = [regex]::Match($htmlContent, 'Release Date[:\s]*</[^>]+>\s*<[^>]+>([^<]+)<')
            }
            if (-not $issuedMatch.Success) {
                $issuedMatch = [regex]::Match($htmlContent, '"datePublished"[:\s]*"([^"]+)"')
            }
            if ($issuedMatch.Success) {
                $issuedDateRaw = $issuedMatch.Groups[1].Value.Trim()
                $result.Issued_Date = $issuedDateRaw
                $result.Fixed_Date = $issuedDateRaw
            }

            # Extract Updated Date
            $updatedMatch = [regex]::Match($htmlContent, 'Updated[:\s]*</[^>]+>\s*<[^>]+>([^<]+)<')
            if (-not $updatedMatch.Success) {
                $updatedMatch = [regex]::Match($htmlContent, 'Updated[:\s]*([A-Za-z]+\s+\d{1,2},?\s+\d{4})')
            }
            if (-not $updatedMatch.Success) {
                $updatedMatch = [regex]::Match($htmlContent, '"dateModified"[:\s]*"([^"]+)"')
            }
            if ($updatedMatch.Success) {
                $result.Updated_Date = $updatedMatch.Groups[1].Value.Trim()
            }

            # Extract CVEs
            $cveMatches = [regex]::Matches($htmlContent, '(CVE-\d{4}-\d{4,})')
            $cveList = @()
            foreach ($cveMatch in $cveMatches) {
                $cveList += $cveMatch.Groups[1].Value
            }
            $result.CVEs = ($cveList | Select-Object -Unique) -join "; "

            # Extract Affected Products
            $productMatches = [regex]::Matches($htmlContent, 'Red Hat Enterprise Linux[^<]*(?:Server|Workstation|Desktop|Client)?[^<]*\d+[^<]*')
            $productList = @()
            foreach ($productMatch in $productMatches) {
                $product = $productMatch.Value.Trim() -replace '\s+', ' '
                if ($product.Length -gt 5 -and $product.Length -lt 100) {
                    $productList += $product
                }
            }
            if ($productList.Count -eq 0) {
                $productMatches = [regex]::Matches($htmlContent, '<li[^>]*>([^<]*Red Hat[^<]*)</li>')
                foreach ($productMatch in $productMatches) {
                    $productList += $productMatch.Groups[1].Value.Trim()
                }
            }
            $result.Affected_Products = ($productList | Select-Object -Unique | Select-Object -First 5) -join "; "

            # Extract Description
            $descMatch = [regex]::Match($htmlContent, 'Description[:\s]*</h[^>]+>\s*<[^>]+>([^<]+(?:<[^>]+>[^<]+)*)</[^>]+>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            if (-not $descMatch.Success) {
                $descMatch = [regex]::Match($htmlContent, '<div[^>]*class="[^"]*description[^"]*"[^>]*>([^<]+(?:<[^>]+>[^<]+)*)</div>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            }
            if (-not $descMatch.Success) {
                $descMatch = [regex]::Match($htmlContent, 'security\s+(?:update|fix|patch)[^.]*\.', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if ($descMatch.Success) {
                $desc = $descMatch.Groups[1].Value -replace '<[^>]+>', ' ' -replace '\s+', ' '
                $result.Description = $desc.Trim().Substring(0, [Math]::Min(500, $desc.Trim().Length))
            }

            $result.Fetch_Status = "Success"
        }
        else {
            $result.Fetch_Status = "HTTP Status: $($response.StatusCode)"
        }
    }
    catch [System.Net.WebException] {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        if ($statusCode -eq 404) {
            Write-Warning "RHSA $RHSAID not found (404)"
            $result.Fetch_Status = "Not Found (404)"
        }
        elseif ($statusCode -eq 403) {
            Write-Warning "Access denied for $RHSAID (403)"
            $result.Fetch_Status = "Access Denied (403)"
        }
        else {
            Write-Warning "Network error fetching $RHSAID : $_"
            $result.Fetch_Status = "Network Error: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Warning "Error fetching $RHSAID : $_"
        $result.Fetch_Status = "Error: $($_.Exception.Message)"
    }

    # Calculate Patching Status based on Fixed Date
    $result.Patching_Status = Get-PatchingStatus -FixedDate $result.Fixed_Date

    return $result
}

function Extract-RHSAIDs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $rhsaIDs = @()

    try {
        if (-not (Test-Path $FilePath)) {
            throw "Input file not found: $FilePath"
        }

        $content = Get-Content -Path $FilePath -ErrorAction Stop

        foreach ($line in $content) {
            # Regex pattern to match RHSA-YYYY-NNNNN or RHSA-YYYY:NNNNN format
            $regexMatches = [regex]::Matches($line, 'RHSA-\d{4}[:-]\d{4,5}')

            foreach ($match in $regexMatches) {
                $rhsaID = $match.Value

                # Normalize format: convert dash to colon for the number part
                # RHSA-2025-18281 should become RHSA-2025:18281
                if ($rhsaID -match '^RHSA-(\d{4})-(\d{4,5})$') {
                    $rhsaID = "RHSA-$($Matches[1]):$($Matches[2])"
                }

                $rhsaIDs += $rhsaID
            }
        }

        # Remove duplicates
        $rhsaIDs = $rhsaIDs | Select-Object -Unique

        Write-Host "Found $($rhsaIDs.Count) unique RHSA ID(s) in the input file." -ForegroundColor Green

        return $rhsaIDs
    }
    catch {
        Write-Error "Error reading input file: $_"
        return @()
    }
}

function Convert-DateFormat {
    param (
        [Parameter(Mandatory=$false)]
        [string]$DateString
    )

    if ([string]::IsNullOrWhiteSpace($DateString)) {
        return ""
    }

    try {
        $parsedDate = $null
        $dateFormats = @(
            "MMMM d, yyyy",
            "MMMM dd, yyyy",
            "MMM d, yyyy",
            "MMM dd, yyyy",
            "yyyy-MM-dd",
            "MM/dd/yyyy",
            "dd/MM/yyyy",
            "yyyy-MM-ddTHH:mm:ss",
            "yyyy-MM-ddTHH:mm:ssZ"
        )

        foreach ($format in $dateFormats) {
            if ([DateTime]::TryParseExact($DateString.Trim(), $format, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
                return $parsedDate.ToString("yyyy-MM-dd")
            }
        }

        if ([DateTime]::TryParse($DateString, [ref]$parsedDate)) {
            return $parsedDate.ToString("yyyy-MM-dd")
        }

        return $DateString
    }
    catch {
        return $DateString
    }
}

# ============================================
# MAIN SCRIPT EXECUTION
# ============================================

Clear-Host
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   RHSA Vulnerability Tracker Script v2.0" -ForegroundColor Yellow
Write-Host "   Using Red Hat Errata URL" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Check if input file exists
$scriptPath = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptPath)) {
    $scriptPath = Get-Location
}

$inputFilePath = Join-Path -Path $scriptPath -ChildPath $InputFile
$outputFilePath = Join-Path -Path $scriptPath -ChildPath $OutputFile

# If input file not in script directory, check current directory
if (-not (Test-Path $inputFilePath)) {
    $inputFilePath = $InputFile
}

Write-Host "Configuration:" -ForegroundColor Cyan
Write-Host "  Base URL: $RedHatErrataBaseURL" -ForegroundColor Gray
Write-Host "  Input File: $inputFilePath" -ForegroundColor Gray
Write-Host "  Output File: $outputFilePath" -ForegroundColor Gray
Write-Host ""

# Verify input file exists
if (-not (Test-Path $inputFilePath)) {
    Write-Host "ERROR: Input file '$InputFile' not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please create '$InputFile' with RHSA entries in the format:" -ForegroundColor Yellow
    Write-Host "  Red Hat Update for kernel (RHSA-2025:18281)" -ForegroundColor Gray
    Write-Host "  Red Hat Update for kernel (RHSA-2025:19105)" -ForegroundColor Gray
    Write-Host ""

    # Create sample file
    $createSample = Read-Host "Would you like to create a sample input file? (Y/N)"
    if ($createSample -eq 'Y' -or $createSample -eq 'y') {
        $sampleContent = @"
Red Hat Update for kernel (RHSA-2025:18281)
Red Hat Update for kernel (RHSA-2025:19105)
"@
        $sampleContent | Out-File -FilePath $InputFile -Encoding UTF8
        Write-Host "Sample file created: $InputFile" -ForegroundColor Green
        Write-Host "Please edit the file with valid RHSA IDs and run the script again." -ForegroundColor Yellow
    }
    exit 1
}

# Extract RHSA IDs from input file
Write-Host "Extracting RHSA IDs from input file..." -ForegroundColor Cyan
$rhsaList = Extract-RHSAIDs -FilePath $inputFilePath

if ($rhsaList.Count -eq 0) {
    Write-Host "No RHSA IDs found in the input file!" -ForegroundColor Red
    Write-Host "Make sure your file contains entries like: RHSA-2025:18281" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "RHSA IDs to process:" -ForegroundColor Cyan
$rhsaList | ForEach-Object { 
    Write-Host "  - $_ --> $RedHatErrataBaseURL/$_" -ForegroundColor Gray 
}
Write-Host ""

# Process each RHSA ID
$results = @()
$counter = 0
$total = $rhsaList.Count

Write-Host "Starting data fetch from Red Hat Errata..." -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Gray
Write-Host ""

foreach ($rhsaID in $rhsaList) {
    $counter++
    Write-Host "[$counter/$total] " -ForegroundColor White -NoNewline

    $data = Get-RHSADataFromErrata -RHSAID $rhsaID

    # Convert dates to standard format
    $data.Fixed_Date = Convert-DateFormat -DateString $data.Fixed_Date
    $data.Issued_Date = Convert-DateFormat -DateString $data.Issued_Date
    $data.Updated_Date = Convert-DateFormat -DateString $data.Updated_Date

    # Recalculate patching status with converted date
    $data.Patching_Status = Get-PatchingStatus -FixedDate $data.Fixed_Date

    $results += $data

    # Display status
    if ($data.Fetch_Status -eq "Success") {
        Write-Host "  --> Severity: $($data.Severity)" -ForegroundColor Green
        Write-Host "  --> Fixed Date: $($data.Fixed_Date)" -ForegroundColor Green
        Write-Host "  --> Status: $($data.Patching_Status)" -ForegroundColor Green
    }
    else {
        Write-Host "  --> Fetch Status: $($data.Fetch_Status)" -ForegroundColor Yellow
        Write-Host "  --> Patching Status: $($data.Patching_Status)" -ForegroundColor Yellow
    }
    Write-Host ""

    # Add delay to avoid rate limiting
    if ($counter -lt $total) {
        Start-Sleep -Seconds 1
    }
}

# Export to CSV
Write-Host "============================================" -ForegroundColor Gray
Write-Host "Exporting results to CSV..." -ForegroundColor Cyan

try {
    $results | Select-Object `
        RHSA_ID, `
        Synopsis, `
        Advisory_Type, `
        Severity, `
        Issued_Date, `
        Fixed_Date, `
        Updated_Date, `
        Patching_Status, `
        CVEs, `
        Affected_Products, `
        Description, `
        Errata_URL, `
        Fetch_Status | `
    Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   EXPORT COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output file: $outputFilePath" -ForegroundColor White
    Write-Host "Total records processed: $($results.Count)" -ForegroundColor White
    Write-Host ""

    # Summary statistics
    $successCount = ($results | Where-Object { $_.Fetch_Status -eq "Success" }).Count
    $failedCount = ($results | Where-Object { $_.Fetch_Status -ne "Success" }).Count
    $fixedThisMonth = ($results | Where-Object { $_.Patching_Status -eq "vulnerability fixed on this month" }).Count
    $fixedNextMonth = ($results | Where-Object { $_.Patching_Status -like "*next month*" }).Count
    $notRedHat = ($results | Where-Object { $_.Patching_Status -eq "not redhat product to fix" }).Count

    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Successfully fetched    : $successCount" -ForegroundColor Gray
    Write-Host "  Failed to fetch         : $failedCount" -ForegroundColor Gray
    Write-Host "  ----------------------------------------" -ForegroundColor Gray
    Write-Host "  Fixed this month        : $fixedThisMonth" -ForegroundColor Green
    Write-Host "  Fix next month          : $fixedNextMonth" -ForegroundColor Yellow
    Write-Host "  Not RedHat product      : $notRedHat" -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Error "Error exporting to CSV: $_"
    exit 1
}

# Display results in console table
Write-Host "Results Preview:" -ForegroundColor Cyan
Write-Host "----------------" -ForegroundColor Cyan
$results | Format-Table -Property RHSA_ID, Severity, Fixed_Date, Patching_Status, Fetch_Status -AutoSize

Write-Host ""
Write-Host "Script execution completed successfully!" -ForegroundColor Green
Write-Host "Open '$OutputFile' to view the full report." -ForegroundColor White
Write-Host ""
