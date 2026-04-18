#Requires -Version 5.1
<#
.SYNOPSIS
    RHSA Vulnerability Tracker Script
.DESCRIPTION
    Extracts RHSA IDs from rhsa_list.txt, fetches security data from Red Hat Errata page,
    and generates a CSV report with patching status based on fix dates.
.NOTES
    Author: Security Automation Script
    Version: 3.1 - Updated Patching Logic with 3 Conditions
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

    # Check if FixedDate is empty or null
    if ([string]::IsNullOrWhiteSpace($FixedDate)) {
        return "not redhat product to fix"
    }

    try {
        # Parse the ISO date format (YYYY-MM-DD)
        $parsedDate = [DateTime]::ParseExact($FixedDate.Trim(), "yyyy-MM-dd", [System.Globalization.CultureInfo]::InvariantCulture)

        # Calculate reference dates
        $today = Get-Date

        # 16th of last month (1 month ago)
        $lastMonth = $today.AddMonths(-1)
        $sixteenthOfLastMonth = Get-Date -Year $lastMonth.Year -Month $lastMonth.Month -Day 16 -Hour 0 -Minute 0 -Second 0

        # 16th of 2 months ago
        $twoMonthsAgo = $today.AddMonths(-2)
        $sixteenthOfTwoMonthsAgo = Get-Date -Year $twoMonthsAgo.Year -Month $twoMonthsAgo.Month -Day 16 -Hour 0 -Minute 0 -Second 0

        # Apply logic based on conditions
        # Condition 1: Fixed Date < 16th of 2 months ago --> Already fixed (false positive)
        if ($parsedDate -lt $sixteenthOfTwoMonthsAgo) {
            return "Already fixed the vulnerability seems false positive on reporting"
        }
        # Condition 2: Fixed Date >= 16th of 2 months ago AND < 16th of last month --> Fixed this month
        elseif ($parsedDate -ge $sixteenthOfTwoMonthsAgo -and $parsedDate -lt $sixteenthOfLastMonth) {
            return "vulnerability fixed on this month"
        }
        # Condition 3: Fixed Date >= 16th of last month --> Will be fixed next month
        else {
            return "vulnerability will be fixed on next month patching."
        }
    }
    catch {
        # If date parsing fails, return not redhat product
        return "not redhat product to fix"
    }
}

function Get-WebPageWithCurl {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )

    try {
        $curlPath = Get-Command curl.exe -ErrorAction SilentlyContinue
        if (-not $curlPath) {
            Write-Host "    ERROR: curl.exe not found" -ForegroundColor Red
            return $null
        }

        $content = & curl.exe -s -L -k --max-time 120 --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" $Url 2>&1

        if ($content -and $content.Length -gt 500) {
            return $content
        }
        else {
            return $null
        }
    }
    catch {
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
        return $null
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
        Patching_Status   = ""
        Errata_URL        = ""
        Fetch_Status      = ""
    }

    $errataURL = "$RedHatErrataBaseURL/$RHSAID"
    $result.Errata_URL = $errataURL

    Write-Host "  Fetching: $errataURL" -ForegroundColor Cyan

    # Fetch page using curl.exe
    $html = Get-WebPageWithCurl -Url $errataURL

    if ($html) {
        Write-Host "    Page fetched successfully (Length: $($html.Length))" -ForegroundColor Green

        try {
            # ============================================
            # EXTRACT ISSUED DATE (Fixed Pattern)
            # Pattern: <dt>Issued:</dt>\n<dd>2024-03-25</dd>
            # ============================================
            $issuedMatch = [regex]::Match($html, '<dt>\s*Issued:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($issuedMatch.Success) {
                $result.Issued_Date = $issuedMatch.Groups[1].Value.Trim()
                $result.Fixed_Date = $issuedMatch.Groups[1].Value.Trim()
                Write-Host "    Issued Date Found: $($result.Issued_Date)" -ForegroundColor Green
            }
            else {
                Write-Host "    Issued Date: NOT FOUND" -ForegroundColor Yellow
            }

            # ============================================
            # EXTRACT UPDATED DATE
            # Pattern: <dt>Updated:</dt>\n<dd>2024-03-25</dd>
            # ============================================
            $updatedMatch = [regex]::Match($html, '<dt>\s*Updated:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($updatedMatch.Success) {
                $result.Updated_Date = $updatedMatch.Groups[1].Value.Trim()
                Write-Host "    Updated Date Found: $($result.Updated_Date)" -ForegroundColor Green
            }

            # ============================================
            # EXTRACT SYNOPSIS/TITLE
            # Pattern: <h1>RHSA-2024:1485 - Security Advisory</h1>
            # ============================================
            $synopsisMatch = [regex]::Match($html, '<h1>([^<]+)</h1>')
            if ($synopsisMatch.Success) {
                $result.Synopsis = $synopsisMatch.Groups[1].Value.Trim() -replace '\s+', ' '
            }

            # ============================================
            # EXTRACT SEVERITY
            # ============================================
            $severityMatch = [regex]::Match($html, '<dt>\s*Severity:\s*</dt>\s*<dd>\s*([^<]+)\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $severityMatch.Success) {
                $severityMatch = [regex]::Match($html, '(Critical|Important|Moderate|Low)\s*Impact', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if (-not $severityMatch.Success) {
                $severityMatch = [regex]::Match($html, 'Impact:\s*(Critical|Important|Moderate|Low)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if ($severityMatch.Success) {
                $result.Severity = $severityMatch.Groups[1].Value.Trim()
                Write-Host "    Severity Found: $($result.Severity)" -ForegroundColor Green
            }

            # ============================================
            # EXTRACT ADVISORY TYPE
            # ============================================
            $typeMatch = [regex]::Match($html, '<dt>\s*Type:\s*</dt>\s*<dd>\s*([^<]+)\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $typeMatch.Success) {
                $typeMatch = [regex]::Match($html, '(Security Advisory|Bug Fix Advisory|Enhancement Advisory)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if ($typeMatch.Success) {
                $result.Advisory_Type = $typeMatch.Groups[1].Value.Trim()
            }

            # ============================================
            # EXTRACT CVEs
            # ============================================
            $cveMatches = [regex]::Matches($html, '(CVE-\d{4}-\d{4,})')
            $cveList = @()
            foreach ($cveMatch in $cveMatches) {
                $cveList += $cveMatch.Groups[1].Value
            }
            $result.CVEs = ($cveList | Select-Object -Unique) -join "; "
            if ($result.CVEs) {
                Write-Host "    CVEs Found: $($cveList.Count) unique" -ForegroundColor Green
            }

            # ============================================
            # EXTRACT AFFECTED PRODUCTS
            # ============================================
            $productMatches = [regex]::Matches($html, '>(Red Hat Enterprise Linux[^<]{0,50})<')
            $productList = @()
            foreach ($productMatch in $productMatches) {
                $product = $productMatch.Groups[1].Value.Trim() -replace '\s+', ' '
                if ($product.Length -gt 10 -and $product.Length -lt 80) {
                    $productList += $product
                }
            }
            $result.Affected_Products = ($productList | Select-Object -Unique | Select-Object -First 5) -join "; "

            $result.Fetch_Status = "Success"
        }
        catch {
            $result.Fetch_Status = "Parse Error: $($_.Exception.Message)"
            Write-Host "    Parse Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        $result.Fetch_Status = "Connection Failed"
        Write-Host "    Connection Failed" -ForegroundColor Red
    }

    # ============================================
    # CALCULATE PATCHING STATUS
    # ============================================
    $result.Patching_Status = Get-PatchingStatus -FixedDate $result.Fixed_Date
    Write-Host "    Patching Status: $($result.Patching_Status)" -ForegroundColor $(
        if ($result.Patching_Status -like "*false positive*") { "Magenta" }
        elseif ($result.Patching_Status -eq "vulnerability fixed on this month") { "Green" }
        elseif ($result.Patching_Status -like "*next month*") { "Yellow" }
        else { "Red" }
    )

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
            $regexMatches = [regex]::Matches($line, 'RHSA-\d{4}[:-]\d{4,5}')

            foreach ($match in $regexMatches) {
                $rhsaID = $match.Value

                # Normalize format: convert dash to colon
                if ($rhsaID -match '^RHSA-(\d{4})-(\d{4,5})$') {
                    $rhsaID = "RHSA-$($Matches[1]):$($Matches[2])"
                }

                $rhsaIDs += $rhsaID
            }
        }

        $rhsaIDs = $rhsaIDs | Select-Object -Unique

        return $rhsaIDs
    }
    catch {
        Write-Error "Error reading input file: $_"
        return @()
    }
}

# ============================================
# MAIN SCRIPT EXECUTION
# ============================================

Clear-Host
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   RHSA Vulnerability Tracker Script v3.1" -ForegroundColor Yellow
Write-Host "   Updated Patching Logic (3 Conditions)" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Check if curl.exe is available
$curlCheck = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlCheck) {
    Write-Host "ERROR: curl.exe not found!" -ForegroundColor Red
    Write-Host "This script requires curl.exe (built into Windows 10/11)" -ForegroundColor Yellow
    exit 1
}
Write-Host "curl.exe found: $($curlCheck.Source)" -ForegroundColor Green
Write-Host ""

# Display current date info for reference
$today = Get-Date
$lastMonth = $today.AddMonths(-1)
$twoMonthsAgo = $today.AddMonths(-2)
$sixteenthOfLastMonth = Get-Date -Year $lastMonth.Year -Month $lastMonth.Month -Day 16
$sixteenthOfTwoMonthsAgo = Get-Date -Year $twoMonthsAgo.Year -Month $twoMonthsAgo.Month -Day 16

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   DATE REFERENCE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Today's Date              : $($today.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  16th of Last Month        : $($sixteenthOfLastMonth.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  16th of 2 Months Ago      : $($sixteenthOfTwoMonthsAgo.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   PATCHING LOGIC" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Condition 1:" -ForegroundColor Magenta
Write-Host "    Fixed Date < $($sixteenthOfTwoMonthsAgo.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> Already fixed the vulnerability seems false positive on reporting" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Condition 2:" -ForegroundColor Green
Write-Host "    Fixed Date >= $($sixteenthOfTwoMonthsAgo.ToString('yyyy-MM-dd')) AND < $($sixteenthOfLastMonth.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> vulnerability fixed on this month" -ForegroundColor Green
Write-Host ""
Write-Host "  Condition 3:" -ForegroundColor Yellow
Write-Host "    Fixed Date >= $($sixteenthOfLastMonth.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> vulnerability will be fixed on next month patching." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Condition 4:" -ForegroundColor Red
Write-Host "    No Fixed Date" -ForegroundColor White
Write-Host "    --> not redhat product to fix" -ForegroundColor Red
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check input file
$scriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$inputFilePath = Join-Path -Path $scriptPath -ChildPath $InputFile
$outputFilePath = Join-Path -Path $scriptPath -ChildPath $OutputFile

if (-not (Test-Path $inputFilePath)) {
    $inputFilePath = $InputFile
}

Write-Host "Input File : $inputFilePath" -ForegroundColor Gray
Write-Host "Output File: $outputFilePath" -ForegroundColor Gray
Write-Host ""

# Check if input file exists
if (-not (Test-Path $inputFilePath)) {
    Write-Host "ERROR: Input file '$InputFile' not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Creating sample file..." -ForegroundColor Yellow

    $sampleContent = @"
Red Hat Update for kernel (RHSA-2024:1485)
Red Hat Update for kernel (RHSA-2025:1234)
"@
    $sampleContent | Out-File -FilePath $InputFile -Encoding UTF8
    Write-Host "Sample file created: $InputFile" -ForegroundColor Green
    Write-Host "Please edit the file with your RHSA IDs and run again." -ForegroundColor Yellow
    exit 1
}

# Extract RHSA IDs
Write-Host "Extracting RHSA IDs from input file..." -ForegroundColor Cyan
$rhsaList = Extract-RHSAIDs -FilePath $inputFilePath

if ($rhsaList.Count -eq 0) {
    Write-Host "No RHSA IDs found in the input file!" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($rhsaList.Count) RHSA ID(s):" -ForegroundColor Green
$rhsaList | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
Write-Host ""

# Process each RHSA ID
$results = @()
$counter = 0
$total = $rhsaList.Count

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   PROCESSING RHSA IDs" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

foreach ($rhsaID in $rhsaList) {
    $counter++
    Write-Host "[$counter/$total] $rhsaID" -ForegroundColor White
    Write-Host ("-" * 50) -ForegroundColor Gray

    $data = Get-RHSADataFromErrata -RHSAID $rhsaID
    $results += $data

    Write-Host ""

    # Delay between requests to avoid rate limiting
    if ($counter -lt $total) {
        Write-Host "  Waiting 2 seconds before next request..." -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
}

# Export to CSV
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   EXPORTING RESULTS TO CSV" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

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
        Errata_URL, `
        Fetch_Status | `
    Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Host "CSV exported successfully!" -ForegroundColor Green
    Write-Host "File: $outputFilePath" -ForegroundColor White
    Write-Host ""

    # Summary Statistics
    $successCount = ($results | Where-Object { $_.Fetch_Status -eq "Success" }).Count
    $failedCount = ($results | Where-Object { $_.Fetch_Status -ne "Success" }).Count
    $falsePositive = ($results | Where-Object { $_.Patching_Status -like "*false positive*" }).Count
    $fixedThisMonth = ($results | Where-Object { $_.Patching_Status -eq "vulnerability fixed on this month" }).Count
    $fixedNextMonth = ($results | Where-Object { $_.Patching_Status -like "*next month*" }).Count
    $notRedHat = ($results | Where-Object { $_.Patching_Status -eq "not redhat product to fix" }).Count

    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   FINAL SUMMARY" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  FETCH RESULTS:" -ForegroundColor Cyan
    Write-Host "    Total Processed      : $($results.Count)" -ForegroundColor White
    Write-Host "    Successful           : $successCount" -ForegroundColor Green
    Write-Host "    Failed               : $failedCount" -ForegroundColor $(if($failedCount -gt 0){"Red"}else{"Green"})
    Write-Host ""
    Write-Host "  PATCHING STATUS:" -ForegroundColor Cyan
    Write-Host "    False Positive       : $falsePositive" -ForegroundColor Magenta
    Write-Host "    Fixed This Month     : $fixedThisMonth" -ForegroundColor Green
    Write-Host "    Fix Next Month       : $fixedNextMonth" -ForegroundColor Yellow
    Write-Host "    Not RedHat Product   : $notRedHat" -ForegroundColor Red
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""

    # Display results table
    Write-Host "RESULTS TABLE:" -ForegroundColor Cyan
    Write-Host ""
    $results | Format-Table -Property @(
        @{Label="RHSA_ID"; Expression={$_.RHSA_ID}; Width=18},
        @{Label="Fixed_Date"; Expression={$_.Fixed_Date}; Width=12},
        @{Label="Severity"; Expression={$_.Severity}; Width=12},
        @{Label="Patching_Status"; Expression={$_.Patching_Status}; Width=55}
    ) -Wrap

}
catch {
    Write-Error "Error exporting CSV: $_"
}

Write-Host ""
Write-Host "Script completed!" -ForegroundColor Green
Write-Host ""
