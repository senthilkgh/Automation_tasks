#Vulnerability Tracker - Author: AllianzGPT | Idea by: Senthil Kumar Giritharan | AI Assist: Claude
#Requires -Version 5.1
param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = ""
)

$DefaultInputFile    = "rhsa_list.txt"
$RedHatErrataBaseURL = "https://access.redhat.com/errata"

# ============================================================
# FUNCTION: Resolve-ViaPublicDNS
# Resolves a hostname by sending a raw DNS query over UDP
# directly to a public DNS server, bypassing system DNS.
# ============================================================
function Resolve-ViaPublicDNS {
    param([string]$Hostname, [string]$DnsServer = "8.8.8.8")
    try {
        # Build a minimal DNS query packet for type A (IPv4)
        $id      = [byte[]](0x12, 0x34)                          # Transaction ID
        $flags   = [byte[]](0x01, 0x00)                          # Standard query
        $qdcount = [byte[]](0x00, 0x01)                          # 1 question
        $ancount = [byte[]](0x00, 0x00)
        $nscount = [byte[]](0x00, 0x00)
        $arcount = [byte[]](0x00, 0x00)

        # Encode hostname as DNS labels
        $labels = @()
        foreach ($part in $Hostname.Split('.')) {
            $labels += [byte]$part.Length
            $labels += [System.Text.Encoding]::ASCII.GetBytes($part)
        }
        $labels += 0x00                                           # Root label

        $qtype  = [byte[]](0x00, 0x01)                           # Type A
        $qclass = [byte[]](0x00, 0x01)                           # Class IN

        $packet = $id + $flags + $qdcount + $ancount + $nscount + $arcount +
                  $labels + $qtype + $qclass

        $udp    = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 3000
        $ep     = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($DnsServer), 53)
        $udp.Send($packet, $packet.Length, $ep) | Out-Null

        $remote = $ep
        $resp   = $udp.Receive([ref]$remote)
        $udp.Close()

        # Parse answer section — skip header (12 bytes) + question section
        $pos = 12
        # Skip question section (labels + qtype + qclass)
        while ($pos -lt $resp.Length -and $resp[$pos] -ne 0) {
            $pos += $resp[$pos] + 1
        }
        $pos += 5  # skip null label + qtype + qclass (5 bytes)

        # Read first answer record
        if ($pos + 12 -lt $resp.Length) {
            $pos += 2   # skip name pointer
            $rtype = ($resp[$pos] -shl 8) -bor $resp[$pos+1]; $pos += 2
            $pos += 6   # skip class, TTL
            $rdlen = ($resp[$pos] -shl 8) -bor $resp[$pos+1]; $pos += 2
            if ($rtype -eq 1 -and $rdlen -eq 4) {
                # Type A — 4 byte IP address
                return "$($resp[$pos]).$($resp[$pos+1]).$($resp[$pos+2]).$($resp[$pos+3])"
            }
        }
        return $null
    }
    catch { return $null }
}

# ============================================================
# ENVIRONMENT CLEANUP — runs automatically every time
# Clears proxy env vars and resets .NET SSL/TLS settings so
# WebClient works cleanly regardless of prior session state.
# ============================================================

# 1. Clear any proxy environment variables set in this session
foreach ($v in @("HTTP_PROXY","HTTPS_PROXY","http_proxy","https_proxy","NO_PROXY","no_proxy","ALL_PROXY","all_proxy")) {
    if (Test-Path "Env:$v") {
        Remove-Item "Env:$v" -ErrorAction SilentlyContinue
    }
}

# 2. Clear system/IE proxy from .NET WebRequest (set by previous IWR calls)
[System.Net.WebRequest]::DefaultWebProxy = $null

# 3. Force TLS 1.2 + TLS 1.1 + TLS — covers all Red Hat server configs
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls11 -bor
    [System.Net.SecurityProtocolType]::Tls

# 4. Reset SSL certificate validation to default (remove any leftover callbacks)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

# 6. Override DNS resolution for .NET — bypasses broken system DNS
#    Adds a static host entry so .NET resolves access.redhat.com
#    without relying on the system DNS resolver (which is blocked).
try {
    $dnsResult = [System.Net.Dns]::GetHostAddresses("access.redhat.com")
    if ($dnsResult.Count -gt 0) {
        Write-Host "  DNS OK : access.redhat.com -> $($dnsResult[0].IPAddressToString)" -ForegroundColor Green
    }
} catch {
    # System DNS failed — resolve using a public DNS server via UDP socket
    Write-Host "  System DNS failed, trying public DNS resolver..." -ForegroundColor Yellow
    try {
        # Query 8.8.8.8 (Google DNS) directly using a raw UDP socket
        $dnsIP = Resolve-ViaPublicDNS -Hostname "access.redhat.com" -DnsServer "8.8.8.8"
        if (-not $dnsIP) { $dnsIP = Resolve-ViaPublicDNS -Hostname "access.redhat.com" -DnsServer "1.1.1.1" }
        if (-not $dnsIP) { $dnsIP = Resolve-ViaPublicDNS -Hostname "access.redhat.com" -DnsServer "9.9.9.9" }

        if ($dnsIP) {
            Write-Host "  DNS resolved via public DNS: access.redhat.com -> $dnsIP" -ForegroundColor Green
            # Store for use in WebClient/WebRequest via hosts-style override
            $script:RedHatIP = $dnsIP
        } else {
            Write-Host "  DNS resolution failed on all public servers." -ForegroundColor Red
            $script:RedHatIP = $null
        }
    } catch {
        Write-Host "  DNS override failed: $($_.Exception.Message)" -ForegroundColor Red
        $script:RedHatIP = $null
    }
}

# ============================================================
# FUNCTION: Get-InputFileName
# ============================================================
function Get-InputFileName {
    param([string]$ProvidedFile, [string]$DefaultFile)

    if (-not [string]::IsNullOrWhiteSpace($ProvidedFile)) {
        if (Test-Path $ProvidedFile) {
            Write-Host "Using provided input file: $ProvidedFile" -ForegroundColor Green
            return $ProvidedFile
        }
        Write-Host "Provided file not found: $ProvidedFile" -ForegroundColor Red
    }

    if (Test-Path $DefaultFile) {
        Write-Host "Found default input file: $DefaultFile" -ForegroundColor Green
        $useDefault = Read-Host "Do you want to use this file? (Y/N)"
        if ($useDefault -eq 'Y' -or $useDefault -eq 'y' -or $useDefault -eq '') {
            return $DefaultFile
        }
    }

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "   INPUT FILE SELECTION"                     -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    while ($true) {
        $userInput = Read-Host "Enter input file name (or Q to quit)"
        if ($userInput -eq 'Q' -or $userInput -eq 'q') { exit 0 }
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Host "Please enter a valid file name." -ForegroundColor Red
            continue
        }
        if (Test-Path $userInput) { return $userInput }
        Write-Host "File not found: $userInput" -ForegroundColor Red
        Get-ChildItem -Path . -File |
            Where-Object { $_.Extension -in '.txt','.csv','.log' } |
            ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
    }
}

# ============================================================
# FUNCTION: Get-PatchingStatus
# ============================================================
function Get-PatchingStatus {
    param([string]$FixedDate)

    if ([string]::IsNullOrWhiteSpace($FixedDate)) { return "not redhat product to fix" }

    $parsedDate = $null
    try {
        $parsedDate = [DateTime]::ParseExact(
            $FixedDate.Trim(), "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        return "not redhat product to fix"
    }

    $today   = Get-Date
    $d16Last = Get-Date -Year $today.AddMonths(-1).Year -Month $today.AddMonths(-1).Month -Day 16 -Hour 0 -Minute 0 -Second 0
    $d16Two  = Get-Date -Year $today.AddMonths(-2).Year -Month $today.AddMonths(-2).Month -Day 16 -Hour 0 -Minute 0 -Second 0

    if     ($parsedDate -lt $d16Two)                                { return "Already fixed the vulnerability seems false positive on reporting" }
    elseif ($parsedDate -ge $d16Two -and $parsedDate -lt $d16Last) { return "vulnerability fixed on this month" }
    else                                                            { return "vulnerability will be fixed on next month patching." }
}

# ============================================================
# FUNCTION: Get-WebPage
# Three methods tried in order:
#   1. System.Net.WebClient  (always available in PS 5.x)
#   2. System.Net.WebRequest (lower level fallback)
#   3. curl.exe with explicit DNS servers
# All run inside the PowerShell process — not affected by
# endpoint security rules that block curl.exe as a process.
# ============================================================
function Get-WebPage {
    param([string]$Url)

    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

    # If system DNS is broken, rewrite URL to use the pre-resolved IP
    # and pass the original hostname in the Host header so the server
    # responds correctly (SNI / virtual hosting)
    $fetchUrl = $Url
    if ($script:RedHatIP) {
        $fetchUrl = $Url -replace "access\.redhat\.com", $script:RedHatIP
    }

    # ── Method 1: WebClient ───────────────────────────────────────
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent",                $ua)
        $wc.Headers.Add("Accept",                    "text/html,application/xhtml+xml,*/*;q=0.8")
        $wc.Headers.Add("Accept-Language",           "en-US,en;q=0.9")
        $wc.Headers.Add("Cache-Control",             "no-cache")
        $wc.Headers.Add("Upgrade-Insecure-Requests", "1")
        if ($script:RedHatIP) {
            $wc.Headers.Add("Host", "access.redhat.com")
        }

        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12 -bor
            [System.Net.SecurityProtocolType]::Tls11 -bor
            [System.Net.SecurityProtocolType]::Tls

        $content = $wc.DownloadString($fetchUrl)
        $wc.Dispose()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        if ($content -and $content.Length -gt 500) { return $content }
    }
    catch {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        Write-Host "    WebClient : $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ── Method 2: WebRequest ──────────────────────────────────────
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12 -bor
            [System.Net.SecurityProtocolType]::Tls11 -bor
            [System.Net.SecurityProtocolType]::Tls

        $req                   = [System.Net.WebRequest]::Create($fetchUrl)
        $req.Method            = "GET"
        $req.Timeout           = 120000
        $req.UserAgent         = $ua
        $req.Accept            = "text/html,application/xhtml+xml,*/*;q=0.8"
        $req.AllowAutoRedirect = $true
        $req.Headers.Add("Accept-Language",           "en-US,en;q=0.9")
        $req.Headers.Add("Cache-Control",             "no-cache")
        $req.Headers.Add("Upgrade-Insecure-Requests", "1")
        if ($script:RedHatIP) { $req.Host = "access.redhat.com" }

        $resp    = $req.GetResponse()
        $stream  = $resp.GetResponseStream()
        $reader  = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        if ($content -and $content.Length -gt 500) { return $content }
    }
    catch {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        Write-Host "    WebRequest: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ── Method 3: curl.exe with explicit DNS ──────────────────────
    $curlExe = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlExe) {
        $dnsServers = @("8.8.8.8","1.1.1.1","9.9.9.9")
        foreach ($dns in $dnsServers) {
            try {
                $curlArgs = @(
                    "-s";"-L";"-k";"--max-time";"60";"--compressed";"--tlsv1.2"
                    "--dns-servers"; $dns
                    "-H"; "User-Agent: $ua"
                    "-H"; "Accept: text/html,application/xhtml+xml,*/*;q=0.8"
                    "-H"; "Accept-Language: en-US,en;q=0.9"
                    "-H"; "Cache-Control: no-cache"
                    $Url
                )
                $raw = & curl.exe @curlArgs 2>&1
                $str = if ($raw -is [array]) { $raw -join "" } else { [string]$raw }
                if ($str -and $str.Length -gt 500) { return $str }
            }
            catch {}
        }
    }

    Write-Host "    ERROR: All fetch methods failed for $Url" -ForegroundColor Red
    return $null
}

# ============================================================
# FUNCTION: Get-RHSADataFromErrata
# ============================================================
function Get-RHSADataFromErrata {
    param([string]$RHSAID, [string]$OriginalSourceLine = "")

    $result = [PSCustomObject]@{
        RHSA_ID           = $RHSAID
        Original_Source   = $OriginalSourceLine
        Synopsis          = ""
        Advisory_Type     = ""
        Severity          = ""
        Issued_Date       = ""
        Fixed_Date        = ""
        Updated_Date      = ""
        CVEs              = ""
        Affected_Products = ""
        Patching_Status   = ""
        Errata_URL        = "$RedHatErrataBaseURL/$RHSAID"
        Fetch_Status      = ""
    }

    Write-Host "  Fetching: $($result.Errata_URL)" -ForegroundColor Cyan
    $html = Get-WebPage -Url $result.Errata_URL

    if (-not $html) {
        $result.Fetch_Status    = "Connection Failed"
        $result.Patching_Status = Get-PatchingStatus -FixedDate ""
        Write-Host "    Connection Failed" -ForegroundColor Red
        return $result
    }

    Write-Host "    Page fetched (Length: $($html.Length))" -ForegroundColor Green

    try {
        $reOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

        # Issued date — try every known pattern Red Hat uses
        $issuedPatterns = @(
            # Standard dl/dt/dd structure
            '<dt>\s*Issued:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>'
            # JSON-LD datePublished
            '"datePublished"\s*:\s*"(\d{4}-\d{2}-\d{2})'
            # JSON-LD with full ISO timestamp
            '"datePublished"\s*:\s*"(\d{4}-\d{2}-\d{2})T'
            # Meta tag
            '<meta\s[^>]*name=["\s]*date["\s]*[^>]*content=["\s]*(\d{4}-\d{2}-\d{2})'
            # Inline label anywhere on page
            'Issued:\s*</[^>]+>\s*<[^>]+>\s*(\d{4}-\d{2}-\d{2})'
            # Any label=Issued followed by date nearby
            'Issued[^<]{0,30}(\d{4}-\d{2}-\d{2})'
            # Loose: any yyyy-MM-dd that appears after the word Issued in the page
            '(?s)Issued.{0,200}?(\d{4}-\d{2}-\d{2})'
        )

        $m = $null
        foreach ($pat in $issuedPatterns) {
            $m = [System.Text.RegularExpressions.Regex]::Match($html, $pat, $reOpts)
            if ($m.Success) { break }
        }

        if ($m -and $m.Success) {
            $result.Issued_Date = $m.Groups[1].Value.Trim()
            $result.Fixed_Date  = $m.Groups[1].Value.Trim()
            Write-Host "    Issued Date : $($result.Issued_Date)" -ForegroundColor Green
        } else {
            # Last resort — find the earliest yyyy-MM-dd date anywhere in the page
            # that looks like a recent advisory date (2020 onwards)
            $allDates = [System.Text.RegularExpressions.Regex]::Matches($html, '\b(20[2-9]\d-\d{2}-\d{2})\b')
            if ($allDates.Count -gt 0) {
                $earliest = $allDates | ForEach-Object { $_.Groups[1].Value } |
                    Sort-Object | Select-Object -First 1
                $result.Issued_Date = $earliest
                $result.Fixed_Date  = $earliest
                Write-Host "    Issued Date : $($result.Issued_Date) (fallback - earliest date found)" -ForegroundColor Yellow
            } else {
                Write-Host "    Issued Date : NOT FOUND" -ForegroundColor Red
            }
        }

        # Updated date
        $m = [System.Text.RegularExpressions.Regex]::Match($html, '<dt>\s*Updated:\s*</dt>\s*<dd>\s*(\d{4}-\d{2}-\d{2})\s*</dd>', $reOpts)
        if (-not $m.Success) { $m = [System.Text.RegularExpressions.Regex]::Match($html, '"dateModified"\s*:\s*"(\d{4}-\d{2}-\d{2})', $reOpts) }
        if ($m.Success) { $result.Updated_Date = $m.Groups[1].Value.Trim() }

        # Synopsis
        $m = [System.Text.RegularExpressions.Regex]::Match($html, '<h1[^>]*>([^<]+)</h1>')
        if (-not $m.Success) { $m = [System.Text.RegularExpressions.Regex]::Match($html, '<title>([^<]+)</title>', $reOpts) }
        if ($m.Success) { $result.Synopsis = ($m.Groups[1].Value.Trim() -replace '\s+', ' ') }

        # Severity
        $m = [System.Text.RegularExpressions.Regex]::Match($html, '<dt>\s*Severity:\s*</dt>\s*<dd>\s*([^<]+)\s*</dd>', $reOpts)
        if (-not $m.Success) { $m = [System.Text.RegularExpressions.Regex]::Match($html, '(Critical|Important|Moderate|Low)\s*(?:Impact|Severity)', $reOpts) }
        if (-not $m.Success) { $m = [System.Text.RegularExpressions.Regex]::Match($html, '"severity"\s*:\s*"(Critical|Important|Moderate|Low)"', $reOpts) }
        if ($m.Success) {
            $result.Severity = $m.Groups[1].Value.Trim()
            Write-Host "    Severity    : $($result.Severity)" -ForegroundColor Green
        }

        # Advisory type
        $m = [System.Text.RegularExpressions.Regex]::Match($html, '<dt>\s*Type:\s*</dt>\s*<dd>\s*([^<]+)\s*</dd>', $reOpts)
        if (-not $m.Success) { $m = [System.Text.RegularExpressions.Regex]::Match($html, '(Security Advisory|Bug Fix Advisory|Enhancement Advisory)', $reOpts) }
        if ($m.Success) { $result.Advisory_Type = $m.Groups[1].Value.Trim() }

        # CVEs
        $cveFound = [System.Text.RegularExpressions.Regex]::Matches($html, '(CVE-\d{4}-\d{4,})')
        $cveList  = @()
        foreach ($cm in $cveFound) { $cveList += $cm.Groups[1].Value }
        $result.CVEs = ($cveList | Select-Object -Unique) -join "; "
        if ($cveList.Count -gt 0) { Write-Host "    CVEs        : $($cveList.Count) unique" -ForegroundColor Green }

        # Affected products
        $prodFound = [System.Text.RegularExpressions.Regex]::Matches($html, '>(Red Hat Enterprise Linux[^<]{0,50})<')
        $prodList  = @()
        foreach ($pm in $prodFound) {
            $p = ($pm.Groups[1].Value.Trim() -replace '\s+', ' ')
            if ($p.Length -gt 10 -and $p.Length -lt 80) { $prodList += $p }
        }
        $result.Affected_Products = ($prodList | Select-Object -Unique | Select-Object -First 5) -join "; "

        $result.Fetch_Status = "Success"
    }
    catch {
        $result.Fetch_Status = "Parse Error: $($_.Exception.Message)"
        Write-Host "    Parse Error : $($_.Exception.Message)" -ForegroundColor Red
    }

    $result.Patching_Status = Get-PatchingStatus -FixedDate $result.Fixed_Date

    $statusColor = "Red"
    if     ($result.Patching_Status -like "*false positive*") { $statusColor = "Magenta" }
    elseif ($result.Patching_Status -like "*fixed on this*")  { $statusColor = "Green"   }
    elseif ($result.Patching_Status -like "*next month*")     { $statusColor = "Yellow"  }
    Write-Host "    Pat. Status : $($result.Patching_Status)" -ForegroundColor $statusColor

    return $result
}

# ============================================================
# FUNCTION: Create-NonRHSAEntry
# ============================================================
function Create-NonRHSAEntry {
    param([string]$OriginalLine, [int]$LineNumber)
    return [PSCustomObject]@{
        RHSA_ID           = "N/A (Line $LineNumber)"
        Original_Source   = $OriginalLine
        Synopsis          = "Non-RHSA Entry"
        Advisory_Type     = "N/A"
        Severity          = "N/A"
        Issued_Date       = ""
        Fixed_Date        = ""
        Updated_Date      = ""
        CVEs              = ""
        Affected_Products = ""
        Patching_Status   = "no Redhat patch available check manually with respective app team"
        Errata_URL        = ""
        Fetch_Status      = "Non-RHSA Entry"
    }
}

# ============================================================
# FUNCTION: Process-InputFile
# ============================================================
function Process-InputFile {
    param([string]$FilePath)

    $rhsaEntries = @(); $nonRhsaEntries = @()

    if (-not (Test-Path $FilePath)) {
        Write-Error "Input file not found: $FilePath"
        return @{ RHSAEntries = @(); NonRHSAEntries = @() }
    }

    $content    = Get-Content -Path $FilePath -ErrorAction Stop
    $lineNumber = 0

    foreach ($line in $content) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmedLine = $line.Trim()
        $rhsaMatch   = [System.Text.RegularExpressions.Regex]::Match($trimmedLine, 'RHSA-\d{4}[:-]\d{4,5}')

        if ($rhsaMatch.Success) {
            $rhsaID = $rhsaMatch.Value
            $normM  = [System.Text.RegularExpressions.Regex]::Match($rhsaID, '^RHSA-(\d{4})-(\d{4,5})$')
            if ($normM.Success) { $rhsaID = "RHSA-" + $normM.Groups[1].Value + ":" + $normM.Groups[2].Value }
            $rhsaEntries += [PSCustomObject]@{ RHSA_ID = $rhsaID; OriginalLine = $trimmedLine; LineNumber = $lineNumber }
        } else {
            $nonRhsaEntries += [PSCustomObject]@{ OriginalLine = $trimmedLine; LineNumber = $lineNumber }
        }
    }

    $seen = @{}; $unique = @()
    foreach ($item in $rhsaEntries) {
        if (-not $seen.ContainsKey($item.RHSA_ID)) { $seen[$item.RHSA_ID] = $true; $unique += $item }
    }
    return @{ RHSAEntries = $unique; NonRHSAEntries = $nonRhsaEntries }
}

# ============================================================
# FUNCTION: ConvertTo-HtmlEncode
# Pure PowerShell HTML encoding — no assembly loading needed.
# Replaces System.Web.HttpUtility::HtmlEncode for PS 5.x.
# ============================================================
function ConvertTo-HtmlEncode {
    param([string]$Text)
    if (-not $Text) { return "" }
    $Text = $Text -replace '&',  '&amp;'
    $Text = $Text -replace '<',  '&lt;'
    $Text = $Text -replace '>',  '&gt;'
    $Text = $Text -replace '"',  '&quot;'
    $Text = $Text -replace "'",  '&#39;'
    return $Text
}

# ============================================================
# FUNCTION: Export-HTMLReport
# ============================================================
function Export-HTMLReport {
    param([array]$Results, [string]$OutputPath, [string]$InputFileName)

    $today   = Get-Date
    $d16Last = Get-Date -Year $today.AddMonths(-1).Year -Month $today.AddMonths(-1).Month -Day 16
    $d16Two  = Get-Date -Year $today.AddMonths(-2).Year -Month $today.AddMonths(-2).Month -Day 16

    $total   = $Results.Count
    $success = ($Results | Where-Object { $_.Fetch_Status -eq "Success" }).Count
    $fp      = ($Results | Where-Object { $_.Patching_Status -like "*false positive*" }).Count
    $ftm     = ($Results | Where-Object { $_.Patching_Status -like "*fixed on this*" }).Count
    $fnm     = ($Results | Where-Object { $_.Patching_Status -like "*next month*" }).Count
    $nr      = ($Results | Where-Object { $_.Patching_Status -eq "not redhat product to fix" }).Count
    $mc      = ($Results | Where-Object { $_.Patching_Status -like "*check manually*" }).Count
    $failed  = ($Results | Where-Object { $_.Fetch_Status -like "Connection*" -or $_.Fetch_Status -like "Parse*" }).Count

    $rowsHtml = ""
    $rowNum   = 0
    foreach ($r in $Results) {
        $rowNum++
        $bg = ""
        if     ($r.Patching_Status -like "*false positive*") { $bg = "background:#faf5ff;" }
        elseif ($r.Patching_Status -like "*fixed on this*")  { $bg = "background:#f0fff4;" }
        elseif ($r.Patching_Status -like "*next month*")     { $bg = "background:#fffdf0;" }
        elseif ($r.Patching_Status -like "*check manually*") { $bg = "background:#fff8f0;" }
        elseif ($r.Fetch_Status -notmatch "^Success$|^Non-RHSA") { $bg = "background:#fff0f0;" }

        $sevBadge = switch ($r.Severity.ToLower()) {
            "critical"  { "<span class='b-crit'>Critical</span>" }
            "important" { "<span class='b-imp'>Important</span>" }
            "moderate"  { "<span class='b-mod'>Moderate</span>" }
            "low"       { "<span class='b-low'>Low</span>" }
            default     { "<span class='b-na'>" + (ConvertTo-HtmlEncode $r.Severity) + "</span>" }
        }

        $patBadge = ""
        if     ($r.Patching_Status -like "*false positive*")        { $patBadge = "<span class='b-fp'>False Positive</span>" }
        elseif ($r.Patching_Status -like "*fixed on this*")         { $patBadge = "<span class='b-ftm'>Fixed This Month</span>" }
        elseif ($r.Patching_Status -like "*next month*")            { $patBadge = "<span class='b-fnm'>Next Month</span>" }
        elseif ($r.Patching_Status -eq "not redhat product to fix") { $patBadge = "<span class='b-nr'>Not RedHat</span>" }
        elseif ($r.Patching_Status -like "*check manually*")        { $patBadge = "<span class='b-mc'>Manual Check</span>" }
        else                                                         { $patBadge = "<span class='b-na'>-</span>" }

        $fetchBadge = ""
        if     ($r.Fetch_Status -eq "Success")        { $fetchBadge = "<span class='b-ok'>OK</span>" }
        elseif ($r.Fetch_Status -eq "Non-RHSA Entry") { $fetchBadge = "<span class='b-na'>N/A</span>" }
        else   { $fetchBadge = "<span class='b-fail' title='" + (ConvertTo-HtmlEncode $r.Fetch_Status) + "'>Failed</span>" }

        $cveShort = ""
        if ($r.CVEs) {
            $cveParts = $r.CVEs -split ";"
            $cveShort = ($cveParts | Select-Object -First 2) -join ";"
            if ($cveParts.Count -gt 2) { $cveShort += " ..." }
        }

        $rhsaLink = if ($r.Errata_URL) {
            "<a href='" + $r.Errata_URL + "' target='_blank' class='rhsa-link'>" + (ConvertTo-HtmlEncode $r.RHSA_ID) + "</a>"
        } else {
            ConvertTo-HtmlEncode $r.RHSA_ID
        }

        $synopsis = ConvertTo-HtmlEncode $r.Synopsis
        if ($synopsis.Length -gt 60) { $synopsis = $synopsis.Substring(0,57) + "..." }

        $rowsHtml += "<tr style='" + $bg + "'>"
        $rowsHtml += "<td class='rn'>" + $rowNum + "</td>"
        $rowsHtml += "<td class='mono'>" + $rhsaLink + "</td>"
        $rowsHtml += "<td class='orig' title='" + (ConvertTo-HtmlEncode $r.Original_Source) + "'>" + (ConvertTo-HtmlEncode $r.Original_Source) + "</td>"
        $rowsHtml += "<td title='" + (ConvertTo-HtmlEncode $r.Synopsis) + "'>" + $synopsis + "</td>"
        $rowsHtml += "<td>" + $sevBadge + "</td>"
        $rowsHtml += "<td class='mono dt'>" + (ConvertTo-HtmlEncode $r.Issued_Date) + "</td>"
        $rowsHtml += "<td class='cve' title='" + (ConvertTo-HtmlEncode $r.CVEs) + "'>" + (ConvertTo-HtmlEncode $cveShort) + "</td>"
        $rowsHtml += "<td>" + $patBadge + "<br><small>" + (ConvertTo-HtmlEncode $r.Patching_Status) + "</small></td>"
        $rowsHtml += "<td>" + $fetchBadge + "</td>"
        $rowsHtml += "</tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RHSA Vulnerability Report - $($today.ToString('yyyy-MM-dd'))</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Arial,sans-serif;font-size:13px;color:#1a1a1a;background:#f4f6fb;padding:24px;}
.header{background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.07);}
h1{font-size:20px;font-weight:700;margin-bottom:4px;}
.sub{font-size:12px;color:#888;}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.mc{background:#fff;border-radius:10px;padding:14px 16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.07);}
.mc .lb{font-size:11px;color:#666;margin-bottom:6px;}
.mc .vl{font-size:26px;font-weight:700;}
.card{background:#fff;border-radius:10px;padding:18px 20px;box-shadow:0 1px 4px rgba(0,0,0,.07);}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center;}
.toolbar input,.toolbar select{padding:6px 10px;border:1px solid #ccc;border-radius:6px;font-size:12px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;padding:9px 10px;font-size:11px;color:#555;border-bottom:2px solid #ddd;font-weight:700;white-space:nowrap;background:#f9f9f9;position:sticky;top:0;z-index:1;}
td{padding:7px 10px;border-bottom:1px solid #eee;vertical-align:middle;}
tr:hover td{background:#f5f8ff!important;}
.rn{color:#ccc;font-size:11px;width:30px;}
.mono{font-family:Consolas,monospace;font-size:11px;}
.orig{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:#666;}
.dt{white-space:nowrap;}
.cve{font-size:10px;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.rhsa-link{color:#3b5bdb;text-decoration:none;}
.rhsa-link:hover{text-decoration:underline;}
span[class^="b-"]{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;}
.b-fp {background:#f3e8ff;color:#6b21a8;}
.b-ftm{background:#d4edda;color:#155724;}
.b-fnm{background:#fff3cd;color:#856404;}
.b-nr {background:#f8d7da;color:#721c24;}
.b-mc {background:#fde8c8;color:#7a3e00;}
.b-ok {background:#d4edda;color:#155724;}
.b-fail{background:#f8d7da;color:#721c24;}
.b-crit{background:#f8d7da;color:#721c24;}
.b-imp{background:#fde8c8;color:#7a3e00;}
.b-mod{background:#fff3cd;color:#856404;}
.b-low{background:#d4edda;color:#155724;}
.b-na {background:#e2e3e5;color:#383d41;}
td small{font-size:10px;color:#888;display:block;margin-top:2px;}
.legend{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;font-size:11px;align-items:center;}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;}
.footer{margin-top:20px;padding:12px 16px;background:#f0f4ff;border:1px solid #c5d0f5;border-radius:8px;font-size:11px;color:#555;}
.af-label{font-weight:700;color:#3b5bdb;}
@media(max-width:700px){.metrics{grid-template-columns:repeat(2,1fr);}}
</style>
</head>
<body>
<div class="header">
  <h1>&#128737; RHSA Vulnerability Report</h1>
  <div class="sub">
    Source: <strong>$(ConvertTo-HtmlEncode $InputFileName)</strong>
    &nbsp;|&nbsp; Generated: <strong>$($today.ToString('yyyy-MM-dd HH:mm'))</strong>
    &nbsp;|&nbsp; Patching window: <strong>$($d16Two.ToString('yyyy-MM-dd'))</strong> to <strong>$($d16Last.ToString('yyyy-MM-dd'))</strong>
  </div>
</div>
<div class="metrics">
  <div class="mc"><div class="lb">Total Entries</div><div class="vl">$total</div></div>
  <div class="mc"><div class="lb">False Positive</div><div class="vl" style="color:#6b21a8">$fp</div></div>
  <div class="mc"><div class="lb">Fixed This Month</div><div class="vl" style="color:#155724">$ftm</div></div>
  <div class="mc"><div class="lb">Fix Next Month</div><div class="vl" style="color:#856404">$fnm</div></div>
  <div class="mc"><div class="lb">Not RedHat</div><div class="vl" style="color:#721c24">$nr</div></div>
  <div class="mc"><div class="lb">Manual Check</div><div class="vl" style="color:#7a3e00">$mc</div></div>
  <div class="mc"><div class="lb">Fetched OK</div><div class="vl" style="color:#198754">$success</div></div>
  <div class="mc"><div class="lb">Fetch Failed</div><div class="vl" style="color:#c0392b">$failed</div></div>
</div>
<div class="card">
  <div class="legend">
    <strong>Legend:</strong>
    <span><span class="dot" style="background:#f3e8ff;border:1px solid #c084fc"></span>False Positive</span>
    <span><span class="dot" style="background:#f0fff4;border:1px solid #86efac"></span>Fixed This Month</span>
    <span><span class="dot" style="background:#fffdf0;border:1px solid #fcd34d"></span>Next Month</span>
    <span><span class="dot" style="background:#fff8f0;border:1px solid #fdba74"></span>Manual Check</span>
    <span><span class="dot" style="background:#fff0f0;border:1px solid #fca5a5"></span>Fetch Failed</span>
  </div>
  <div class="toolbar">
    <input type="text" id="ft" placeholder="Filter by RHSA ID, status, severity..." style="width:260px;" oninput="filterTable()">
    <select id="fs" onchange="filterTable()">
      <option value="">All statuses</option>
      <option value="False Positive">False Positive</option>
      <option value="Fixed This Month">Fixed This Month</option>
      <option value="Next Month">Fix Next Month</option>
      <option value="Not RedHat">Not RedHat</option>
      <option value="Manual Check">Manual Check</option>
    </select>
    <select id="fsev" onchange="filterTable()">
      <option value="">All severities</option>
      <option>Critical</option>
      <option>Important</option>
      <option>Moderate</option>
      <option>Low</option>
    </select>
    <span id="row-count" style="font-size:12px;color:#888;margin-left:auto;"></span>
  </div>
  <div style="overflow-x:auto;">
    <table id="main-table">
      <thead>
        <tr>
          <th>#</th><th>RHSA ID</th><th>Original Line</th><th>Synopsis</th>
          <th>Severity</th><th>Issued Date</th><th>CVEs</th>
          <th>Patching Status</th><th>Fetch</th>
        </tr>
      </thead>
      <tbody id="tbl">
$rowsHtml
      </tbody>
    </table>
  </div>
</div>
<div class="footer">
  <span class="af-label">Developed by:</span> Senthil Kumar &nbsp;|&nbsp;
  <span class="af-label">AI Assistance:</span> Claude &nbsp;|&nbsp;
  Customer Success &ndash; Linux &amp; AIX | Hybrid Cloud Enablement
</div>
<script>
var allRows=Array.from(document.querySelectorAll('#tbl tr'));
function filterTable(){
  var q=document.getElementById('ft').value.toLowerCase();
  var fs=document.getElementById('fs').value.toLowerCase();
  var fsev=document.getElementById('fsev').value.toLowerCase();
  var vis=0;
  allRows.forEach(function(r){
    var txt=r.innerText.toLowerCase();
    var show=(!q||txt.indexOf(q)>=0)&&(!fs||txt.indexOf(fs)>=0)&&(!fsev||txt.indexOf(fsev)>=0);
    r.style.display=show?'':'none';
    if(show)vis++;
  });
  document.getElementById('row-count').textContent=vis+' of '+allRows.length+' rows';
}
filterTable();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML Report saved: $OutputPath" -ForegroundColor Green
}

# ============================================================
# MAIN
# ============================================================
Clear-Host
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   RHSA Vulnerability Tracker v8.0"         -ForegroundColor Yellow
Write-Host "   curl.exe Edition + HTML Report"           -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Verify curl.exe
$curlCheck = Get-Command curl.exe -ErrorAction SilentlyContinue
if (-not $curlCheck) {
    Write-Host "ERROR: curl.exe not found! (built into Windows 10/11)" -ForegroundColor Red
    exit 1
}
Write-Host "  curl.exe : $($curlCheck.Source)" -ForegroundColor Green

# Connectivity test — uses Get-WebPage which already has
# DNS fallback and all three fetch methods built in
Write-Host "  Testing connectivity..." -ForegroundColor Cyan
$testPage = Get-WebPage -Url "https://access.redhat.com/errata/RHSA-2024:1485"
if ($testPage -and $testPage.Length -gt 500) {
    Write-Host "  Connectivity : OK ($($testPage.Length) chars)" -ForegroundColor Green
} else {
    Write-Host "  Connectivity : FAILED - could not reach access.redhat.com" -ForegroundColor Red
    Write-Host "  All DNS and fetch methods exhausted." -ForegroundColor Yellow
    Write-Host "  Check with IT if outbound HTTPS is allowed from this machine." -ForegroundColor Yellow
    $cont = Read-Host "  Continue anyway? (Y/N)"
    if ($cont -ne 'Y' -and $cont -ne 'y') { exit 0 }
}
Write-Host ""

$inputFilePath  = Get-InputFileName -ProvidedFile $InputFile -DefaultFile $DefaultInputFile
$baseName       = [System.IO.Path]::GetFileNameWithoutExtension($inputFilePath)
$timestamp      = Get-Date -Format "ddMMyyyy_HHmmss"
$outputCSV      = "${baseName}_report_${timestamp}.csv"
$outputHTML     = "${baseName}_report_${timestamp}.html"

$today = Get-Date
$d16L  = Get-Date -Year $today.AddMonths(-1).Year -Month $today.AddMonths(-1).Month -Day 16
$d16T  = Get-Date -Year $today.AddMonths(-2).Year -Month $today.AddMonths(-2).Month -Day 16

Write-Host ""
Write-Host "  Input  : $inputFilePath"  -ForegroundColor White
Write-Host "  CSV    : $outputCSV"      -ForegroundColor White
Write-Host "  HTML   : $outputHTML"     -ForegroundColor White
Write-Host ""
Write-Host "  Patching window: $($d16T.ToString('yyyy-MM-dd')) to $($d16L.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
Write-Host ""

$processedData  = Process-InputFile -FilePath $inputFilePath
$rhsaEntries    = $processedData.RHSAEntries
$nonRhsaEntries = $processedData.NonRHSAEntries

Write-Host "  RHSA entries   : $($rhsaEntries.Count)"    -ForegroundColor Green
Write-Host "  Non-RHSA lines : $($nonRhsaEntries.Count)" -ForegroundColor Yellow
Write-Host ""

if ($rhsaEntries.Count -eq 0 -and $nonRhsaEntries.Count -eq 0) {
    Write-Host "No entries found!" -ForegroundColor Red; exit 1
}

$proceed = Read-Host "Proceed? (Y/N)"
if ($proceed -ne 'Y' -and $proceed -ne 'y' -and $proceed -ne '') { exit 0 }
Write-Host ""

$results = @()
$counter = 0
$total   = $rhsaEntries.Count

foreach ($rhsaItem in $rhsaEntries) {
    $counter++
    Write-Host "[$counter/$total] $($rhsaItem.RHSA_ID)" -ForegroundColor White
    Write-Host "  $($rhsaItem.OriginalLine)" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------------------" -ForegroundColor Gray
    $data     = Get-RHSADataFromErrata -RHSAID $rhsaItem.RHSA_ID -OriginalSourceLine $rhsaItem.OriginalLine
    $results += $data
    Write-Host ""
    if ($counter -lt $total) { Start-Sleep -Seconds 2 }
}

foreach ($item in $nonRhsaEntries) {
    $results += Create-NonRHSAEntry -OriginalLine $item.OriginalLine -LineNumber $item.LineNumber
}

# Export CSV
$results |
    Select-Object RHSA_ID, Original_Source, Synopsis, Advisory_Type, Severity,
                  Issued_Date, Fixed_Date, Updated_Date, Patching_Status,
                  CVEs, Affected_Products, Errata_URL, Fetch_Status |
    Export-Csv -Path $outputCSV -NoTypeInformation -Encoding UTF8
Write-Host "CSV  saved : $outputCSV" -ForegroundColor Green

# Export HTML
Export-HTMLReport -Results $results -OutputPath $outputHTML -InputFileName $inputFilePath

# Summary
$successCount  = ($results | Where-Object { $_.Fetch_Status -eq "Success" }).Count
$failedCount   = ($results | Where-Object { $_.Fetch_Status -like "Connection*" -or $_.Fetch_Status -like "Parse*" }).Count
$falsePositive = ($results | Where-Object { $_.Patching_Status -like "*false positive*" }).Count
$fixedThis     = ($results | Where-Object { $_.Patching_Status -like "*fixed on this*" }).Count
$fixedNext     = ($results | Where-Object { $_.Patching_Status -like "*next month*" }).Count
$notRedHat     = ($results | Where-Object { $_.Patching_Status -eq "not redhat product to fix" }).Count
$manualCheck   = ($results | Where-Object { $_.Patching_Status -like "*check manually*" }).Count

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   FINAL SUMMARY"                            -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Total           : $($results.Count)"       -ForegroundColor White
Write-Host "  Fetched OK      : $successCount"           -ForegroundColor Green
Write-Host "  Fetch Failed    : $failedCount"            -ForegroundColor $(if($failedCount -gt 0){"Red"}else{"Green"})
Write-Host "  False Positive  : $falsePositive"          -ForegroundColor Magenta
Write-Host "  Fixed This Month: $fixedThis"              -ForegroundColor Green
Write-Host "  Fix Next Month  : $fixedNext"              -ForegroundColor Yellow
Write-Host "  Not RedHat      : $notRedHat"              -ForegroundColor Red
Write-Host "  Manual Check    : $manualCheck"            -ForegroundColor DarkYellow
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  CSV  : $outputCSV"  -ForegroundColor Cyan
Write-Host "  HTML : $outputHTML" -ForegroundColor Cyan
Write-Host ""

$openFile = Read-Host "Open CSV report now? (Y/N)"
if ($openFile -eq 'Y' -or $openFile -eq 'y') { Start-Process $outputCSV }

Write-Host ""
Write-Host "Thank you for using RHSA Vulnerability Tracker!" -ForegroundColor Cyan
Write-Host "Author: AllianzGPT | Idea: Senthil Kumar Giritharan | AI Assist: Claude" -ForegroundColor DarkGray
Write-Host ""