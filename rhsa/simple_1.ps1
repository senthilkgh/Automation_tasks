param([Parameter(Mandatory=$false)][string[]]$RHSAIds,[Parameter(Mandatory=$false)][string]$InputFile,[Parameter(Mandatory=$false)][string]$OutputPath="RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv")
function Get-RHSADataFromWeb{param([string]$RHSAID)
try{Write-Host "Fetching: $RHSAID" -ForegroundColor Cyan
$url="https://access.redhat.com/errata/$RHSAID"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12
$webClient=New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$html=$webClient.DownloadString($url)
$result=[PSCustomObject]@{RHSAID=$RHSAID;CreatedDate="N/A";UpdatedDate="N/A";PackagesImpacted="N/A";FixedDate="N/A"}
$issuedMatch=[regex]::Match($html,'Issued:(\d{4}-\d{2}-\d{2})')
if($issuedMatch.Success){$dateValue=$issuedMatch.Groups[1].Value;$result.CreatedDate=(Get-Date $dateValue -Format "dd-MM-yyyy");$result.FixedDate=$result.CreatedDate;Write-Host "  Issued: $dateValue" -ForegroundColor Green}
$updatedMatch=[regex]::Match($html,'Updated:(\d{4}-\d{2}-\d{2})')
if($updatedMatch.Success){$dateValue=$updatedMatch.Groups[1].Value;$result.UpdatedDate=(Get-Date $dateValue -Format "dd-MM-yyyy");Write-Host "  Updated: $dateValue" -ForegroundColor Green}
if($result.CreatedDate -eq "N/A" -or $result.UpdatedDate -eq "N/A"){$plainText=$html -replace '<[^>]+>','' -replace '\s+',' '
if($plainText -match 'Issued[:\s]*(\d{4})-(\d{2})-(\d{2})'){$dateValue="$($matches[1])-$($matches[2])-$($matches[3])";if($result.CreatedDate -eq "N/A"){$result.CreatedDate=(Get-Date $dateValue -Format "dd-MM-yyyy");$result.FixedDate=$result.CreatedDate}}
if($plainText -match 'Updated[:\s]*(\d{4})-(\d{2})-(\d{2})'){$dateValue="$($matches[1])-$($matches[2])-$($matches[3])";if($result.UpdatedDate -eq "N/A"){$result.UpdatedDate=(Get-Date $dateValue -Format "dd-MM-yyyy")}}}
if($result.UpdatedDate -eq "N/A" -and $result.CreatedDate -ne "N/A"){$result.UpdatedDate=$result.CreatedDate}
$packages=@()
$packagePatterns=@('([\w\-\.]+)-(\d+[\w\.\-]+)\.(x86_64|noarch)\.rpm','([\w\-]+)-(\d[\w\.\-]+)\.el\d+[^\s]*\.(x86_64|noarch)')
foreach($pattern in $packagePatterns){$matches=[regex]::Matches($html,$pattern);foreach($match in $matches){if($match.Groups.Count -ge 4){$pkgName="$($match.Groups[1].Value)-$($match.Groups[2].Value).$($match.Groups[3].Value)";if($packages -notcontains $pkgName -and $pkgName -notmatch 'src\.rpm'){$packages+=$pkgName}}}
if($packages.Count -gt 0){break}}
if($packages.Count -gt 0){$uniquePackages=$packages|Select-Object -Unique|Sort-Object|Select-Object -First 50;$result.PackagesImpacted=$uniquePackages -join "; ";Write-Host "  Packages: $($uniquePackages.Count)" -ForegroundColor Green}
Write-Host "  Success!" -ForegroundColor Green
return $result}catch{Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red;return $null}}
Write-Host "";Write-Host "========================================" -ForegroundColor Green;Write-Host "  RHSA Security Data Scraper" -ForegroundColor Green;Write-Host "========================================" -ForegroundColor Green;Write-Host ""
if($InputFile){if(Test-Path $InputFile){$RHSAIds=Get-Content $InputFile|Where-Object{$_.Trim() -ne "" -and $_ -notmatch "^#"}|ForEach-Object{$_.Trim()};Write-Host "Input: $InputFile ($($RHSAIds.Count) RHSAs)" -ForegroundColor Yellow;Write-Host ""}else{Write-Host "ERROR: File not found" -ForegroundColor Red;exit 1}}elseif($RHSAIds){Write-Host "Processing: $($RHSAIds.Count) RHSA(s)" -ForegroundColor Yellow;Write-Host ""}else{Write-Host "ERROR: No RHSA IDs!" -ForegroundColor Red;Write-Host "";Write-Host "Usage:" -ForegroundColor Yellow;Write-Host "  .\rhsa-scraper.ps1 -RHSAIds 'RHSA-2025:23382'" -ForegroundColor Cyan;Write-Host "  .\rhsa-scraper.ps1 -InputFile 'rhsa-list.txt'" -ForegroundColor Cyan;Write-Host "";exit 1}
$outputDir=Split-Path -Path $OutputPath -Parent;if($outputDir -and -not(Test-Path $outputDir)){try{New-Item -ItemType Directory -Path $outputDir -Force|Out-Null}catch{$OutputPath=Split-Path -Path $OutputPath -Leaf}}
$results=@();$total=$RHSAIds.Count
for($i=0;$i -lt $total;$i++){$current=$i+1;Write-Host "[$current/$total]" -ForegroundColor Cyan;$data=Get-RHSADataFromWeb -RHSAID $RHSAIds[$i].Trim();if($data){$results+=$data};Write-Host "";if($current -lt $total){Start-Sleep -Seconds 2}}
Write-Host "========================================" -ForegroundColor Green;Write-Host ""
if($results.Count -gt 0){try{$results|Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8;Write-Host "SUCCESS!" -ForegroundColor Green;Write-Host "File: $OutputPath" -ForegroundColor Cyan;Write-Host "Records: $($results.Count)" -ForegroundColor Green;Write-Host "";$results|Format-Table -Property RHSAID,CreatedDate,UpdatedDate,FixedDate -AutoSize;Write-Host "";$openFile=Read-Host "Open CSV? (Y/N)";if($openFile -eq "Y" -or $openFile -eq "y"){Start-Process $OutputPath}}catch{Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red;$fallbackPath="RHSA_Report_$(Get-Date -Format 'ddMMyyyy_HHmmss').csv";$results|Export-Csv -Path $fallbackPath -NoTypeInformation -Encoding UTF8;Write-Host "Saved: $fallbackPath" -ForegroundColor Yellow;Start-Process $fallbackPath}}else{Write-Host "ERROR: No data!" -ForegroundColor Red}
Write-Host "";Write-Host "Done!" -ForegroundColor Green;Write-Host ""
