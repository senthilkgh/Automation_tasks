#Vulnerability Tracker Author AlianzGPT with Idea by Senthil Kumar Giritharan
#Requires -Version 5.1
<#
.SYNOPSIS
    RHSA Vulnerability Tracker Script
.DESCRIPTION
    Extracts RHSA IDs from input file, fetches security data from Red Hat Errata page,
    and generates a CSV report with patching status based on fix dates.
    Lines without RHSA IDs are also included with manual check status.
.NOTES
    Author: Security Automation Script
    Version: 3.3 - Auto Input File Detection & Non-RHSA Line Handling
.EXAMPLE
    .\RHSA_Tracker.ps1
    .\RHSA_Tracker.ps1 -InputFile "my_vulnerabilities.txt"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = ""
)

# ============================================
# CONFIGURATION
# ============================================
$DefaultInputFile = "rhsa_list.txt"
$OutputFile = "rhsa_vulnerability_report.csv"
$RedHatErrataBaseURL = "https://access.redhat.com/errata"

# ============================================
# FUNCTIONS
# ============================================

function Get-InputFileName {
    param(
        [string]$ProvidedFile,
        [string]$DefaultFile
    )

    # If file was provided as parameter
    if (-not [string]::IsNullOrWhiteSpace($ProvidedFile)) {
        if (Test-Path $ProvidedFile) {
            Write-Host "Using provided input file: $ProvidedFile" -ForegroundColor Green
            return $ProvidedFile
        }
        else {
            Write-Host "Provided file '$ProvidedFile' not found!" -ForegroundColor Red
        }
    }

    # Check if default file exists
    if (Test-Path $DefaultFile) {
        Write-Host "Found default input file: $DefaultFile" -ForegroundColor Green
        $useDefault = Read-Host "Do you want to use this file? (Y/N)"
        if ($useDefault -eq 'Y' -or $useDefault -eq 'y' -or $useDefault -eq '') {
            return $DefaultFile
        }
    }

    # Ask user for file name
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "   INPUT FILE SELECTION" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please enter the input file name/path." -ForegroundColor Cyan
    Write-Host "The file should contain vulnerability entries (one per line)." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Example file content:" -ForegroundColor Gray
    Write-Host "  Red Hat Update for kernel (RHSA-2024:1485)" -ForegroundColor DarkGray
    Write-Host "  Red Hat Update for httpd (RHSA-2025:1234)" -ForegroundColor DarkGray
    Write-Host "  Windows Update KB5001234 - Security Fix" -ForegroundColor DarkGray
    Write-Host "  Apache Tomcat vulnerability CVE-2024-1234" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        $userInput = Read-Host "Enter input file name (or 'Q' to quit)"

        if ($userInput -eq 'Q' -or $userInput -eq 'q') {
            Write-Host "Exiting script." -ForegroundColor Yellow
            exit 0
        }

        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Host "Please enter a valid file name." -ForegroundColor Red
            continue
        }

        if (Test-Path $userInput) {
            Write-Host "File found: $userInput" -ForegroundColor Green
            return $userInput
        }
        else {
            Write-Host "File '$userInput' not found. Please try again." -ForegroundColor Red

            # Show files in current directory
            Write-Host ""
            Write-Host "Files in current directory:" -ForegroundColor Cyan
            Get-ChildItem -Path . -File | Where-Object { $_.Extension -in '.txt', '.csv', '.log' } | ForEach-Object {
                Write-Host "  - $($_.Name)" -ForegroundColor Gray
            }
            Write-Host ""
        }
    }
}

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
        if ($parsedDate -lt $sixteenthOfTwoMonthsAgo) {
            return "Already fixed the vulnerability seems false positive on reporting"
        }
        elseif ($parsedDate -ge $sixteenthOfTwoMonthsAgo -and $parsedDate -lt $sixteenthOfLastMonth) {
            return "vulnerability fixed on this month"
        }
        else {
            return "vulnerability will be fixed on next month patching."
        }
    }
    catch {
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
        [string]$RHSAID,

        [Parameter(Mandatory=$false)]
        [string]$OriginalSourceLine = ""
    )

    $result = [PSCustomObject]@{
        RHSA_ID             = $RHSAID
        Original_Source     = $OriginalSourceLine
        Synopsis            = ""
        Advisory_Type       = ""
        Severity            = ""
        Issued_Date         = ""
        Fixed_Date          = ""
        Updated_Date        = ""
        CVEs                = ""
        Affected_Products   = ""
        Patching_Status     = ""
        Errata_URL          = ""
        Fetch_Status        = ""
    }

    $errataURL = "$RedHatErrataBaseURL/$RHSAID"
    $result.Errata_URL = $errataURL

    Write-Host "  Fetching: $errataURL" -ForegroundColor Cyan

    # Fetch page using curl.exe
    $html = Get-WebPageWithCurl -Url $errataURL

    if ($html) {
        Write-Host "    Page fetched successfully (Length: $($html.Length))" -ForegroundColor Green

        try {
            # EXTRACT ISSUED DATE
            $issuedMatch = [regex]::Match($html, '<dt>\s*Issued:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($issuedMatch.Success) {
                $result.Issued_Date = $issuedMatch.Groups[1].Value.Trim()
                $result.Fixed_Date = $issuedMatch.Groups[1].Value.Trim()
                Write-Host "    Issued Date Found: $($result.Issued_Date)" -ForegroundColor Green
            }
            else {
                Write-Host "    Issued Date: NOT FOUND" -ForegroundColor Yellow
            }

            # EXTRACT UPDATED DATE
            $updatedMatch = [regex]::Match($html, '<dt>\s*Updated:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($updatedMatch.Success) {
                $result.Updated_Date = $updatedMatch.Groups[1].Value.Trim()
                Write-Host "    Updated Date Found: $($result.Updated_Date)" -ForegroundColor Green
            }

            # EXTRACT SYNOPSIS/TITLE
            $synopsisMatch = [regex]::Match($html, '<h1>([^<]+)</h1>')
            if ($synopsisMatch.Success) {
                $result.Synopsis = $synopsisMatch.Groups[1].Value.Trim() -replace '\s+', ' '
            }

            # EXTRACT SEVERITY
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

            # EXTRACT ADVISORY TYPE
            $typeMatch = [regex]::Match($html, '<dt>\s*Type:\s*</dt>\s*<dd>\s*([^<]+)\s*</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $typeMatch.Success) {
                $typeMatch = [regex]::Match($html, '(Security Advisory|Bug Fix Advisory|Enhancement Advisory)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            if ($typeMatch.Success) {
                $result.Advisory_Type = $typeMatch.Groups[1].Value.Trim()
            }

            # EXTRACT CVEs
            $cveMatches = [regex]::Matches($html, '(CVE-\d{4}-\d{4,})')
            $cveList = @()
            foreach ($cveMatch in $cveMatches) {
                $cveList += $cveMatch.Groups[1].Value
            }
            $result.CVEs = ($cveList | Select-Object -Unique) -join "; "
            if ($result.CVEs) {
                Write-Host "    CVEs Found: $($cveList.Count) unique" -ForegroundColor Green
            }

            # EXTRACT AFFECTED PRODUCTS
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

    # CALCULATE PATCHING STATUS
    $result.Patching_Status = Get-PatchingStatus -FixedDate $result.Fixed_Date
    Write-Host "    Patching Status: $($result.Patching_Status)" -ForegroundColor $(
        if ($result.Patching_Status -like "*false positive*") { "Magenta" }
        elseif ($result.Patching_Status -eq "vulnerability fixed on this month") { "Green" }
        elseif ($result.Patching_Status -like "*next month*") { "Yellow" }
        else { "Red" }
    )

    return $result
}

function Create-NonRHSAEntry {
    param (
        [Parameter(Mandatory=$true)]
        [string]$OriginalLine,

        [Parameter(Mandatory=$true)]
        [int]$LineNumber
    )

    return [PSCustomObject]@{
        RHSA_ID             = "N/A (Line $LineNumber)"
        Original_Source     = $OriginalLine
        Synopsis            = "Non-RHSA Entry"
        Advisory_Type       = "N/A"
        Severity            = "N/A"
        Issued_Date         = ""
        Fixed_Date          = ""
        Updated_Date        = ""
        CVEs                = ""
        Affected_Products   = ""
        Patching_Status     = "no Redhat patch available check manually with respective app team"
        Errata_URL          = ""
        Fetch_Status        = "Non-RHSA Entry"
    }
}

function Process-InputFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $allEntries = @()
    $rhsaEntries = @()
    $nonRhsaEntries = @()

    try {
        if (-not (Test-Path $FilePath)) {
            throw "Input file not found: $FilePath"
        }

        $content = Get-Content -Path $FilePath -ErrorAction Stop
        $lineNumber = 0

        foreach ($line in $content) {
            $lineNumber++

            # Skip empty lines
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $trimmedLine = $line.Trim()

            # Check if line contains RHSA ID
            $rhsaMatch = [regex]::Match($trimmedLine, 'RHSA-\d{4}[:-]\d{4,5}')

            if ($rhsaMatch.Success) {
                $rhsaID = $rhsaMatch.Value

                # Normalize format: convert dash to colon
                if ($rhsaID -match '^RHSA-(\d{4})-(\d{4,5})$') {
                    $rhsaID = "RHSA-$($Matches[1]):$($Matches[2])"
                }

                $rhsaEntries += [PSCustomObject]@{
                    RHSA_ID      = $rhsaID
                    OriginalLine = $trimmedLine
                    LineNumber   = $lineNumber
                    Type         = "RHSA"
                }
            }
            else {
                # Non-RHSA line
                $nonRhsaEntries += [PSCustomObject]@{
                    RHSA_ID      = "N/A"
                    OriginalLine = $trimmedLine
                    LineNumber   = $lineNumber
                    Type         = "Non-RHSA"
                }
            }
        }

        # Remove duplicate RHSA IDs (keep first occurrence)
        $uniqueRHSA = @{}
        $uniqueRhsaEntries = @()
        foreach ($item in $rhsaEntries) {
            if (-not $uniqueRHSA.ContainsKey($item.RHSA_ID)) {
                $uniqueRHSA[$item.RHSA_ID] = $true
                $uniqueRhsaEntries += $item
            }
        }

        return @{
            RHSAEntries    = $uniqueRhsaEntries
            NonRHSAEntries = $nonRhsaEntries
            TotalLines     = $lineNumber
        }
    }
    catch {
        Write-Error "Error reading input file: $_"
        return @{
            RHSAEntries    = @()
            NonRHSAEntries = @()
            TotalLines     = 0
        }
    }
}

# ============================================
# MAIN SCRIPT EXECUTION
# ============================================

Clear-Host
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   RHSA Vulnerability Tracker Script v3.3" -ForegroundColor Yellow
Write-Host "   Auto Input & Non-RHSA Line Handling" -ForegroundColor Yellow
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

# Get input file (auto-detect or ask user)
$inputFilePath = Get-InputFileName -ProvidedFile $InputFile -DefaultFile $DefaultInputFile

# Set output file name based on input file
$inputFileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($inputFilePath)
$outputFilePath = "$inputFileBaseName`_vulnerability_report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   FILE CONFIGURATION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Input File  : $inputFilePath" -ForegroundColor White
Write-Host "  Output File : $outputFilePath" -ForegroundColor White
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
Write-Host "  Condition 1: (False Positive)" -ForegroundColor Magenta
Write-Host "    Fixed Date < $($sixteenthOfTwoMonthsAgo.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> Already fixed the vulnerability seems false positive on reporting" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Condition 2: (Fixed This Month)" -ForegroundColor Green
Write-Host "    Fixed Date >= $($sixteenthOfTwoMonthsAgo.ToString('yyyy-MM-dd')) AND < $($sixteenthOfLastMonth.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> vulnerability fixed on this month" -ForegroundColor Green
Write-Host ""
Write-Host "  Condition 3: (Fix Next Month)" -ForegroundColor Yellow
Write-Host "    Fixed Date >= $($sixteenthOfLastMonth.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "    --> vulnerability will be fixed on next month patching." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Condition 4: (Not RedHat)" -ForegroundColor Red
Write-Host "    No Fixed Date / No RHSA ID" -ForegroundColor White
Write-Host "    --> not redhat product to fix" -ForegroundColor Red
Write-Host ""
Write-Host "  Condition 5: (Non-RHSA Entry)" -ForegroundColor DarkYellow
Write-Host "    Line without RHSA ID" -ForegroundColor White
Write-Host "    --> no Redhat patch available check manually with respective app team" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Process input file
Write-Host "Processing input file..." -ForegroundColor Cyan
$processedData = Process-InputFile -FilePath $inputFilePath

$rhsaEntries = $processedData.RHSAEntries
$nonRhsaEntries = $processedData.NonRHSAEntries

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   INPUT FILE ANALYSIS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Total Lines (non-empty)   : $($rhsaEntries.Count + $nonRhsaEntries.Count)" -ForegroundColor White
Write-Host "  Lines with RHSA IDs       : $($rhsaEntries.Count)" -ForegroundColor Green
Write-Host "  Lines without RHSA IDs    : $($nonRhsaEntries.Count)" -ForegroundColor Yellow
Write-Host ""

if ($rhsaEntries.Count -eq 0 -and $nonRhsaEntries.Count -eq 0) {
    Write-Host "No entries found in the input file!" -ForegroundColor Red
    exit 1
}

# Display RHSA entries
if ($rhsaEntries.Count -gt 0) {
    Write-Host "RHSA Entries Found:" -ForegroundColor Green
    foreach ($item in $rhsaEntries) {
        Write-Host "  [$($item.LineNumber)] $($item.RHSA_ID)" -ForegroundColor Gray
        Write-Host "       $($item.OriginalLine)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# Display Non-RHSA entries
if ($nonRhsaEntries.Count -gt 0) {
    Write-Host "Non-RHSA Entries Found (will be marked for manual check):" -ForegroundColor Yellow
    foreach ($item in $nonRhsaEntries) {
        Write-Host "  [$($item.LineNumber)] $($item.OriginalLine)" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

# Confirm to proceed
$proceed = Read-Host "Do you want to proceed with fetching RHSA data? (Y/N)"
if ($proceed -ne 'Y' -and $proceed -ne 'y' -and $proceed -ne '') {
    Write-Host "Operation cancelled by user." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

# Process RHSA entries
$results = @()
$counter = 0
$total = $rhsaEntries.Count

if ($total -gt 0) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   PROCESSING RHSA ENTRIES" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($rhsaItem in $rhsaEntries) {
        $counter++
        Write-Host "[$counter/$total] $($rhsaItem.RHSA_ID)" -ForegroundColor White
        Write-Host "  Line $($rhsaItem.LineNumber): $($rhsaItem.OriginalLine)" -ForegroundColor DarkGray
        Write-Host ("-" * 60) -ForegroundColor Gray

        $data = Get-RHSADataFromErrata -RHSAID $rhsaItem.RHSA_ID -OriginalSourceLine $rhsaItem.OriginalLine
        $results += $data

        Write-Host ""

        # Delay between requests
        if ($counter -lt $total) {
            Write-Host "  Waiting 2 seconds before next request..." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
    }
}

# Add Non-RHSA entries to results
if ($nonRhsaEntries.Count -gt 0) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "   ADDING NON-RHSA ENTRIES" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($nonRhsaItem in $nonRhsaEntries) {
        Write-Host "  Adding Line $($nonRhsaItem.LineNumber): $($nonRhsaItem.OriginalLine)" -ForegroundColor DarkYellow

        $nonRhsaResult = Create-NonRHSAEntry -OriginalLine $nonRhsaItem.OriginalLine -LineNumber $nonRhsaItem.LineNumber
        $results += $nonRhsaResult
    }
    Write-Host ""
}

# Export to CSV
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   EXPORTING RESULTS TO CSV" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

try {
    $results | Select-Object `
        RHSA_ID, `
        Original_Source, `
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
    $failedCount = ($results | Where-Object { $_.Fetch_Status -eq "Connection Failed" }).Count
    $falsePositive = ($results | Where-Object { $_.Patching_Status -like "*false positive*" }).Count
    $fixedThisMonth = ($results | Where-Object { $_.Patching_Status -eq "vulnerability fixed on this month" }).Count
    $fixedNextMonth = ($results | Where-Object { $_.Patching_Status -like "*next month*" }).Count
    $notRedHat = ($results | Where-Object { $_.Patching_Status -eq "not redhat product to fix" }).Count
    $manualCheck = ($results | Where-Object { $_.Patching_Status -like "*check manually*" }).Count

    Write-Host "============================================" -ForegroundColor Green
    Write-Host "   FINAL SUMMARY" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  FETCH RESULTS:" -ForegroundColor Cyan
    Write-Host "    Total Entries        : $($results.Count)" -ForegroundColor White
    Write-Host "    RHSA Fetched OK      : $successCount" -ForegroundColor Green
    Write-Host "    RHSA Fetch Failed    : $failedCount" -ForegroundColor $(if($failedCount -gt 0){"Red"}else{"Green"})
    Write-Host "    Non-RHSA Entries     : $manualCheck" -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  PATCHING STATUS:" -ForegroundColor Cyan
    Write-Host "    False Positive       : $falsePositive" -ForegroundColor Magenta
    Write-Host "    Fixed This Month     : $fixedThisMonth" -ForegroundColor Green
    Write-Host "    Fix Next Month       : $fixedNextMonth" -ForegroundColor Yellow
    Write-Host "    Not RedHat Product   : $notRedHat" -ForegroundColor Red
    Write-Host "    Manual Check Required: $manualCheck" -ForegroundColor DarkYellow
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
        @{Label="Patching_Status"; Expression={
            if ($_.Patching_Status.Length -gt 50) {
                $_.Patching_Status.Substring(0, 47) + "..."
            } else {
                $_.Patching_Status
            }
        }; Width=55}
    ) -Wrap

}
catch {
    Write-Error "Error exporting CSV: $_"
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   SCRIPT COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output file: $outputFilePath" -ForegroundColor Cyan
Write-Host ""

# Ask if user wants to open the CSV
$openFile = Read-Host "Do you want to open the CSV file now? (Y/N)"
if ($openFile -eq 'Y' -or $openFile -eq 'y') {
    try {
        Start-Process $outputFilePath
    }
    catch {
        Write-Host "Could not open file automatically. Please open manually: $outputFilePath" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Thank you for using RHSA Vulnerability Tracker!" -ForegroundColor Cyan
Write-Host ""
