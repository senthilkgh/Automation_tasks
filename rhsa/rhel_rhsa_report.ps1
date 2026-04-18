# rhsa_collector.ps1
# Purpose: Fetch RHSA data from Red Hat Security API and generate reports
# Requirements: PowerShell 5.1 or higher, Internet connection

<#
.SYNOPSIS
    Fetches RHSA (Red Hat Security Advisory) data and generates reports
.DESCRIPTION
    This script connects to Red Hat Security Data API to fetch RHSA information
    and generates CSV and HTML reports for x86_64 RHEL systems
.PARAMETER InputFile
    Path to file containing RHSA IDs (one per line)
.PARAMETER RhsaIds
    Array of specific RHSA IDs to fetch
.PARAMETER Days
    Fetch RHSAs from last N days (default: 30)
.PARAMETER OutputDir
    Output directory for reports (default: .\reports)
.PARAMETER Format
    Output format: csv, html, or both (default: both)
.EXAMPLE
    .\rhsa_collector.ps1 -InputFile "rhsa_list.txt"
.EXAMPLE
    .\rhsa_collector.ps1 -Days 30
.EXAMPLE
    .\rhsa_collector.ps1 -RhsaIds "RHSA-2024:0001","RHSA-2024:0002"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile,

    [Parameter(Mandatory=$false)]
    [string[]]$RhsaIds,

    [Parameter(Mandatory=$false)]
    [int]$Days = 30,

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\reports",

    [Parameter(Mandatory=$false)]
    [ValidateSet("csv", "html", "both")]
    [string]$Format = "both"
)

# Configuration
#$Script:ApiBase = "https://access.redhat.com/labs/securitydataapi"
$Script:ApiBase = "https://access.redhat.com/hydra/rest/securitydata"
$Script:Arch = "x86_64"
$Script:Product = "rhel"

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Function to fetch RHSA details
function Get-RhsaDetails {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RhsaId
    )

    try {
        Write-Log "Fetching details for $RhsaId..." -Level INFO

        # Fetch CVE data associated with RHSA
        $url = "$Script:ApiBase/cve.json?advisory=$RhsaId"

        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 30 -ErrorAction Stop

        if (-not $response -or $response.Count -eq 0) {
            Write-Log "No data found for $RhsaId" -Level WARNING
            return $null
        }

        # Initialize result object
        $result = [PSCustomObject]@{
            RhsaId      = $RhsaId
            Severity    = "N/A"
            CreatedDate = "N/A"
            UpdatedDate = "N/A"
            PublicDate  = "N/A"
            Synopsis    = "N/A"
            CVEs        = @()
            Packages    = @()
        }

        # Parse response
        foreach ($cveData in $response) {
            # Extract advisory information
            if ($cveData.advisories) {
                foreach ($advisory in $cveData.advisories) {
                    if ($advisory.id -eq $RhsaId) {
                        $result.Severity = if ($advisory.severity) { $advisory.severity } else { "N/A" }
                        $result.CreatedDate = if ($advisory.created_date) { $advisory.created_date } else { "N/A" }
                        $result.UpdatedDate = if ($advisory.updated_date) { $advisory.updated_date } else { "N/A" }
                        $result.PublicDate = if ($advisory.public_date) { $advisory.public_date } else { "N/A" }
                        $result.Synopsis = if ($advisory.synopsis) { $advisory.synopsis } else { "N/A" }
                    }
                }
            }

            # Collect CVEs
            if ($cveData.CVE) {
                $result.CVEs += $cveData.CVE
            }

            # Collect affected packages for x86_64 architecture
            if ($cveData.affected_packages) {
                foreach ($pkg in $cveData.affected_packages) {
                    if ($pkg.arch -match $Script:Arch) {
                        $result.Packages += $pkg.package
                    }
                }
            }
        }

        Write-Log "Successfully fetched $RhsaId" -Level SUCCESS
        return $result

    } catch {
        Write-Log "Error fetching $RhsaId : $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# Function to fetch recent RHSAs
function Get-RecentRhsas {
    param(
        [int]$Days
    )

    try {
        Write-Log "Fetching RHSAs from last $Days days..." -Level INFO

        $endDate = Get-Date
        $startDate = $endDate.AddDays(-$Days)

        $url = "$Script:ApiBase/cvrf.json?after=$($startDate.ToString('yyyy-MM-dd'))&before=$($endDate.ToString('yyyy-MM-dd'))"

        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 30 -ErrorAction Stop

        $rhsaIds = @()
        foreach ($item in $response) {
            if ($item.id -match "^RHSA-") {
                $rhsaIds += $item.id
            }
        }

        Write-Log "Found $($rhsaIds.Count) RHSAs" -Level SUCCESS
        return $rhsaIds

    } catch {
        Write-Log "Error fetching recent RHSAs: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

# Function to generate CSV report
function Export-CsvReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$RhsaData,

        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )

    try {
        Write-Log "Generating CSV report..." -Level INFO

        $csvData = @()

        foreach ($rhsa in $RhsaData) {
            if ($rhsa) {
                $csvData += [PSCustomObject]@{
                    "RHSA_ID"      = $rhsa.RhsaId
                    "Severity"     = $rhsa.Severity
                    "Created_Date" = $rhsa.CreatedDate
                    "Updated_Date" = $rhsa.UpdatedDate
                    "Public_Date"  = $rhsa.PublicDate
                    "Synopsis"     = $rhsa.Synopsis
                    "CVEs"         = ($rhsa.CVEs -join ", ")
                    "Affected_Packages" = (($rhsa.Packages | Select-Object -First 5) -join ", ")
                }
            }
        }

        $csvData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

        Write-Log "CSV report generated: $OutputFile" -Level SUCCESS

    } catch {
        Write-Log "Error generating CSV report: $($_.Exception.Message)" -Level ERROR
    }
}

# Function to generate HTML report
function Export-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$RhsaData,

        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )

    try {
        Write-Log "Generating HTML report..." -Level INFO

        # Calculate statistics
        $stats = @{
            Critical  = ($RhsaData | Where-Object { $_.Severity -eq "Critical" }).Count
            Important = ($RhsaData | Where-Object { $_.Severity -eq "Important" }).Count
            Moderate  = ($RhsaData | Where-Object { $_.Severity -eq "Moderate" }).Count
            Low       = ($RhsaData | Where-Object { $_.Severity -eq "Low" }).Count
            Total     = $RhsaData.Count
        }

        # Build table rows
        $tableRows = ""
        foreach ($rhsa in $RhsaData) {
            if ($rhsa) {
                $severityClass = "severity-$($rhsa.Severity.ToLower())"
                $cveList = ($rhsa.CVEs | Select-Object -First 5) -join ", "

                $tableRows += @"
                <tr>
                    <td><span class="rhsa-id">$($rhsa.RhsaId)</span></td>
                    <td><span class="severity $severityClass">$($rhsa.Severity)</span></td>
                    <td><span class="date">$($rhsa.CreatedDate)</span></td>
                    <td><span class="date">$($rhsa.UpdatedDate)</span></td>
                    <td><span class="synopsis" title="$($rhsa.Synopsis -replace '"', '&quot;')">$($rhsa.Synopsis)</span></td>
                    <td><span class="cve-list">$cveList</span></td>
                </tr>
"@
            }
        }

        # Generate complete HTML
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RHSA Security Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        h1 {
            color: #cc0000;
            margin-bottom: 10px;
            font-size: 2em;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font

-size: 1.1em;
        }
        .metadata {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .metadata-item {
            display: flex;
            flex-direction: column;
        }
        .metadata-label {
            font-weight: bold;
            color: #555;
            font-size: 0.9em;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .metadata-value {
            color: #222;
            font-size: 1.2em;
            font-weight: 600;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card.critical {
            background: linear-gradient(135deg, #d32f2f 0%, #b71c1c 100%);
        }
        .stat-card.important {
            background: linear-gradient(135deg, #f57c00 0%, #e65100 100%);
        }
        .stat-card.moderate {
            background: linear-gradient(135deg, #fbc02d 0%, #f57f17 100%);
        }
        .stat-card.low {
            background: linear-gradient(135deg, #388e3c 0%, #1b5e20 100%);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .stat-label {
            font-size: 1em;
            opacity: 0.95;
            font-weight: 500;
        }
        .filters {
            margin: 25px 0;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .filter-input, .filter-select {
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            flex: 1;
            min-width: 200px;
        }
        .filter-button {
            padding: 12px 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
        }
        .export-buttons {
            margin: 20px 0;
            display: flex;
            gap: 15px;
        }
        .export-btn {
            padding: 12px 25px;
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        thead {
            background: linear-gradient(135deg, #cc0000 0%, #990000 100%);
            color: white;
        }
        th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
        }
        td {
            padding: 15px;
            border-bottom: 1px solid #e0e0e0;
        }
        tbody tr:hover {
            background: #f8f9fa;
        }
        .severity {
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            text-align: center;
            display: inline-block;
            min-width: 90px;
            font-size: 0.85em;
        }
        .severity-critical { background: #d32f2f; color: white; }
        .severity-important { background: #f57c00; color: white; }
        .severity-moderate { background: #fbc02d; color: #333; }
        .severity-low { background: #388e3c; color: white; }
        .rhsa-id {
            font-weight: bold;
            color: #cc0000;
            font-family: 'Courier New', monospace;
        }
        .cve-list {
            font-size: 0.85em;
            color: #666;
            font-family: 'Courier New', monospace;
        }
        .synopsis {
            max-width: 400px;
        }
        .date {
            font-size: 0.9em;
            color: #666;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Red Hat Security Advisory (RHSA) Report</h1>
        <p class="subtitle">Comprehensive Security Advisory Analysis for x86_64 RHEL Systems</p>

        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Generated</span>
                <span class="metadata-value">$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Computer</span>
                <span class="metadata-value">$env:COMPUTERNAME</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Architecture</span>
                <span class="metadata-value">x86_64</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Product</span>
                <span class="metadata-value">RHEL</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Total Advisories</span>
                <span class="metadata-value">$($stats.Total)</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-number">$($stats.Critical)</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card important">
                <div class="stat-number">$($stats.Important)</div>
                <div class="stat-label">Important</div>
            </div>
            <div class="stat-card moderate">
                <div class="stat-number">$($stats.Moderate)</div>
                <div class="stat-label">Moderate</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">$($stats.Low)</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <div class="export-buttons">
            <button class="export-btn" onclick="exportToCSV()">📥 Export CSV</button>
            <button class="export-btn" onclick="window.print()">🖨️ Print Report</button>
        </div>

        <div class="filters">
            <input type="text" class="filter-input" id="searchInput" 
                   placeholder="🔍 Search RHSA ID, CVE, or Synopsis..." 
                   onkeyup="filterTable()">
            <select class="filter-select" id="severityFilter" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="Important">Important</option>
                <option value="Moderate">Moderate</option>
                <option value="Low">Low</option>
            </select>
            <button class="filter-button" onclick="resetFilters()">🔄 Reset</button>
        </div>

        <table id="rhsaTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">RHSA ID ⇅</th>
                    <th onclick="sortTable(1)">Severity ⇅</th>
                    <th onclick="sortTable(2)">Created Date ⇅</th>
                    <th onclick="sortTable(3)">Updated Date ⇅</th>
                    <th>Synopsis</th>
                    <th>CVEs</th>
                </tr>
            </thead>
            <tbody>
$tableRows
            </tbody>
        </table>

        <div class="footer">
            <p><strong>Generated by RHSA Collector PowerShell Script</strong></p>
            <p>Data source: Red Hat Security Data API (https://access.redhat.com/labs/securitydataapi)</p>
            <p>Report generated on Windows machine: $env:COMPUTERNAME</p>
        </div>
    </div>

    <script>
        function filterTable() {
            const searchValue = document.getElementById('searchInput').value.toLowerCase();
            const severityValue = document.getElementById('severityFilter').value;
            const table = document.getElementById('rhsaTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const rhsaId = row.cells[0].textContent.toLowerCase();
                const severity = row.cells[1].textContent;
                const synopsis = row.cells[4].textContent.toLowerCase();
                const cves = row.cells[5].textContent.toLowerCase();

                const matchesSearch = rhsaId.includes(searchValue) || 
                                    synopsis.includes(searchValue) || 
                                    cves.includes(searchValue);
                const matchesSeverity = !severityValue || severity === severityValue;

                row.style.display = (matchesSearch && matchesSeverity) ? '' : 'none';
            }
        }

        function resetFilters() {
            document.getElementById('searchInput').value = '';
            document.getElementById('severityFilter').value = '';
            filterTable();
        }

        function sortTable(columnIndex) {
            const table = document.getElementById('rhsaTable');
            const rows = Array.from(table.rows).slice(1);
            const isAscending = table.rows[0].cells[columnIndex].classList.toggle('asc');

            rows.sort((a, b) => {
                const aValue = a.cells[columnIndex].textContent.trim();
                const bValue = b.cells[columnIndex].textContent.trim();
                return isA

scending ? 
                    aValue.localeCompare(bValue) : 
                    bValue.localeCompare(aValue);
            });

            rows.forEach(row => table.tBodies[0].appendChild(row));
        }

        function exportToCSV() {
            const table = document.getElementById('rhsaTable');
            let csv = [];

            // Headers
            const headers = [];
            for (let cell of table.rows[0].cells) {
                headers.push(cell.textContent.replace('⇅', '').trim());
            }
            csv.push(headers.join(','));

            // Data rows
            for (let i = 1; i < table.rows.length; i++) {
                if (table.rows[i].style.display !== 'none') {
                    const row = [];
                    for (let cell of table.rows[i].cells) {
                        let text = cell.textContent.trim();
                        text = text.replace(/"/g, '""');
                        row.push('"' + text + '"');
                    }
                    csv.push(row.join(','));
                }
            }

            const csvContent = csv.join('\n');
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);

            link.setAttribute('href', url);
            link.setAttribute('download', 'rhsa_report_' + new Date().toISOString().split('T')[0] + '.csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    </script>
</body>
</html>
"@

        $html | Out-File -FilePath $OutputFile -Encoding UTF8

        Write-Log "HTML report generated: $OutputFile" -Level SUCCESS

    } catch {
        Write-Log "Error generating HTML report: $($_.Exception.Message)" -Level ERROR
    }
}

# Main execution
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  RHSA Data Collection Tool" -ForegroundColor Cyan
    Write-Host "  Red Hat Security Advisory Reporter" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $allRhsaData = @()

    # Determine which RHSAs to fetch
    if ($InputFile) {
        # Read from file
        if (-not (Test-Path $InputFile)) {
            Write-Log "Input file not found: $InputFile" -Level ERROR
            exit 1
        }

        Write-Log "Reading RHSA IDs from file: $InputFile" -Level INFO
        $RhsaIds = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch "^#" }
        Write-Log "Found $($RhsaIds.Count) RHSA IDs in file" -Level INFO

    } elseif ($RhsaIds) {
        # Use provided RHSA IDs
        Write-Log "Processing $($RhsaIds.Count) provided RHSA IDs" -Level INFO

    } else {
        # Fetch recent RHSAs
        Write-Log "Fetching recent RHSAs (last $Days days)..." -Level INFO
        $RhsaIds = Get-RecentRhsas -Days $Days

        if ($RhsaIds.Count -eq 0) {
            Write-Log "No RHSAs found for the specified period" -Level WARNING
            exit 0
        }
    }

    # Fetch details for each RHSA
    Write-Host ""
    Write-Log "Fetching details for $($RhsaIds.Count) RHSAs..." -Level INFO
    Write-Host ""

    $progress = 0
    foreach ($rhsaId in $RhsaIds) {
        $progress++
        Write-Progress -Activity "Fetching RHSA Data" -Status "Processing $rhsaId ($progress of $($RhsaIds.Count))" -PercentComplete (($progress / $RhsaIds.Count) * 100)

        $rhsaData = Get-RhsaDetails -RhsaId $rhsaId
        if ($rhsaData) {
            $allRhsaData += $rhsaData
        }

        Start-Sleep -Milliseconds 500  # Rate limiting
    }

    Write-Progress -Activity "Fetching RHSA Data" -Completed

    if ($allRhsaData.Count -eq 0) {
        Write-Log "No data collected. Exiting." -Level WARNING
        exit 0
    }

    Write-Host ""
    Write-Log "Successfully collected data for $($allRhsaData.Count) RHSAs" -Level SUCCESS
    Write-Host ""

    # Generate reports
    $csvFile = Join-Path $OutputDir "rhsa_report_$timestamp.csv"
    $htmlFile = Join-Path $OutputDir "rhsa_report_$timestamp.html"

    if ($Format -eq "csv" -or $Format -eq "both") {
        Export-CsvReport -RhsaData $allRhsaData -OutputFile $csvFile
    }

    if ($Format -eq "html" -or $Format -eq "both") {
        Export-HtmlReport -RhsaData $allRhsaData -OutputFile $htmlFile
    }

    # Display summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Report Generation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Total RHSAs processed: $($allRhsaData.Count)" -ForegroundColor White
    Write-Host "  Critical:  $(($allRhsaData | Where-Object { $_.Severity -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  Important: $(($allRhsaData | Where-Object { $_.Severity -eq 'Important' }).Count)" -ForegroundColor Yellow
    Write-Host "  Moderate:  $(($allRhsaData | Where-Object { $_.Severity -eq 'Moderate' }).Count)" -ForegroundColor Yellow
    Write-Host "  Low:       $(($allRhsaData | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output Files:" -ForegroundColor Cyan

    if ($Format -eq "csv" -or $Format -eq "both") {
        Write-Host "  CSV Report:  $csvFile" -ForegroundColor White
    }
    if ($Format -eq "html" -or $Format -eq "both") {
        Write-Host "  HTML Report: $htmlFile" -ForegroundColor White
    }

    Write-Host ""

    # Open HTML report in browser
    if ($Format -eq "html" -or $Format -eq "both") {
        $openReport = Read-Host "Open HTML report in browser? (Y/N)"
        if ($openReport -eq "Y" -or $openReport -eq "y") {
            Start-Process $htmlFile
        }
    }

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" -Level ERROR
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}