# ============================================
# DIAGNOSTIC SCRIPT - Run this first
# ============================================

# TLS Fix
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls,Tls11,Tls12,Tls13'
} catch {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Test URL - Change this to one of your RHSA IDs
$testRHSA = "RHSA-2024:1485"  # Using a known valid RHSA
$testURL = "https://access.redhat.com/errata/$testRHSA"

Write-Host "============================================" -ForegroundColor Yellow
Write-Host "   DIAGNOSTIC: Checking Red Hat Page" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Testing URL: $testURL" -ForegroundColor Cyan
Write-Host ""

try {
    # Fetch the page
    $response = Invoke-WebRequest -Uri $testURL -UseBasicParsing -TimeoutSec 60
    $html = $response.Content

    Write-Host "Page fetched successfully! Content length: $($html.Length) characters" -ForegroundColor Green
    Write-Host ""

    # Save HTML to file for inspection
    $html | Out-File -FilePath "debug_rhsa_page.html" -Encoding UTF8
    Write-Host "Full HTML saved to: debug_rhsa_page.html" -ForegroundColor Cyan
    Write-Host ""

    # Look for date-related content
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "   SEARCHING FOR DATE PATTERNS" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""

    # Pattern 1: Look for "Issued"
    Write-Host "1. Searching for 'Issued' keyword..." -ForegroundColor Cyan
    $issuedMatches = [regex]::Matches($html, '.{0,50}Issued.{0,100}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($issuedMatches.Count -gt 0) {
        Write-Host "   Found $($issuedMatches.Count) matches:" -ForegroundColor Green
        foreach ($match in $issuedMatches | Select-Object -First 5) {
            Write-Host "   --> $($match.Value -replace '\s+', ' ')" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No 'Issued' found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 2: Look for dates like "March 17, 2026"
    Write-Host "2. Searching for date patterns (Month DD, YYYY)..." -ForegroundColor Cyan
    $dateMatches = [regex]::Matches($html, '(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($dateMatches.Count -gt 0) {
        Write-Host "   Found $($dateMatches.Count) dates:" -ForegroundColor Green
        foreach ($match in $dateMatches | Select-Object -First 10) {
            Write-Host "   --> $($match.Value)" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No dates found in this format" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 3: Look for ISO dates
    Write-Host "3. Searching for ISO date patterns (YYYY-MM-DD)..." -ForegroundColor Cyan
    $isoDateMatches = [regex]::Matches($html, '\d{4}-\d{2}-\d{2}')
    if ($isoDateMatches.Count -gt 0) {
        Write-Host "   Found $($isoDateMatches.Count) ISO dates:" -ForegroundColor Green
        foreach ($match in $isoDateMatches | Select-Object -First 10) {
            Write-Host "   --> $($match.Value)" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No ISO dates found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 4: Look for Release Date
    Write-Host "4. Searching for 'Release Date'..." -ForegroundColor Cyan
    $releaseMatches = [regex]::Matches($html, '.{0,30}Release.{0,30}Date.{0,100}', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($releaseMatches.Count -gt 0) {
        Write-Host "   Found $($releaseMatches.Count) matches:" -ForegroundColor Green
        foreach ($match in $releaseMatches | Select-Object -First 3) {
            Write-Host "   --> $($match.Value -replace '\s+', ' ')" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No 'Release Date' found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 5: Look for table rows with dates
    Write-Host "5. Searching for table data with dates..." -ForegroundColor Cyan
    $tdMatches = [regex]::Matches($html, '<t[hd][^>]*>[^<]*(?:Issued|Updated|Release|Date)[^<]*</t[hd]>\s*<t[hd][^>]*>([^<]+)</t[hd]>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($tdMatches.Count -gt 0) {
        Write-Host "   Found $($tdMatches.Count) table entries:" -ForegroundColor Green
        foreach ($match in $tdMatches) {
            Write-Host "   --> $($match.Groups[1].Value.Trim())" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No table date entries found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 6: Look for dl/dt/dd structure
    Write-Host "6. Searching for definition list (dl/dt/dd) with dates..." -ForegroundColor Cyan
    $dlMatches = [regex]::Matches($html, '<dt[^>]*>[^<]*(?:Issued|Updated|Release)[^<]*</dt>\s*<dd[^>]*>([^<]+)</dd>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($dlMatches.Count -gt 0) {
        Write-Host "   Found $($dlMatches.Count) definition list entries:" -ForegroundColor Green
        foreach ($match in $dlMatches) {
            Write-Host "   --> $($match.Groups[1].Value.Trim())" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No definition list entries found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 7: Look for JSON-LD data
    Write-Host "7. Searching for JSON-LD structured data..." -ForegroundColor Cyan
    $jsonMatches = [regex]::Matches($html, '"datePublished"[:\s]*"([^"]+)"')
    if ($jsonMatches.Count -gt 0) {
        Write-Host "   Found datePublished:" -ForegroundColor Green
        foreach ($match in $jsonMatches) {
            Write-Host "   --> $($match.Groups[1].Value)" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No JSON-LD datePublished found" -ForegroundColor Red
    }
    Write-Host ""

    # Pattern 8: Look for any span/div with date class
    Write-Host "8. Searching for elements with 'date' in class..." -ForegroundColor Cyan
    $classMatches = [regex]::Matches($html, '<[^>]+class="[^"]*date[^"]*"[^>]*>([^<]+)<', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($classMatches.Count -gt 0) {
        Write-Host "   Found $($classMatches.Count) elements:" -ForegroundColor Green
        foreach ($match in $classMatches | Select-Object -First 5) {
            Write-Host "   --> $($match.Groups[1].Value.Trim())" -ForegroundColor Gray
        }
    } else {
        Write-Host "   No date class elements found" -ForegroundColor Red
    }
    Write-Host ""

    # Show a snippet of the HTML around "Issued" if found
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "   HTML SNIPPET AROUND 'Issued'" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    $issuedIndex = $html.IndexOf("Issued", [System.StringComparison]::OrdinalIgnoreCase)
    if ($issuedIndex -gt 0) {
        $start = [Math]::Max(0, $issuedIndex - 100)
        $length = [Math]::Min(500, $html.Length - $start)
        $snippet = $html.Substring($start, $length)
        Write-Host $snippet -ForegroundColor Gray
    } else {
        Write-Host "Could not find 'Issued' in the page" -ForegroundColor Red
    }

}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "   DIAGNOSTIC COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Please share the output above so I can create the correct parsing pattern." -ForegroundColor Yellow
