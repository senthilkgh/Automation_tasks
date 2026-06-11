# ============================================================
#  AutoF5-Snow.ps1
#  Refreshes Firefox Private window every 3 minutes.
#  After refresh, reads visible page text via UI Automation.
#  Plays Windows Exclamation sound + red alert if any of:
#    INC / P1 / P2 / INCIDENT  found anywhere on screen.
#  Stop anytime with: Ctrl+C
# ============================================================

$IntervalSeconds = 60
$IncidentKeywords = @("INC", "P1", "P2", "P3", "P4", "INCIDENT")

# Load UI Automation (reads live DOM text from browser)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinHelper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    public const int SW_RESTORE  = 9;
    public const int SW_MINIMIZE = 2;

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public const byte VK_F5    = 0x74;
    public const uint KEYEVENTF_KEYDOWN = 0x0000;
    public const uint KEYEVENTF_KEYUP   = 0x0002;

    public static void PressF5() {
        keybd_event(VK_F5, 0, KEYEVENTF_KEYDOWN, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(VK_F5, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
}
"@

# Find Firefox Private window handle
function Get-FirefoxPrivateWindowHandle {
    $firefoxProcs = Get-Process -Name "firefox" -ErrorAction SilentlyContinue
    if ($null -eq $firefoxProcs -or $firefoxProcs.Count -eq 0) { return $null }

    $firefoxPIDs = $firefoxProcs | ForEach-Object { $_.Id }
    $script:privateHandle = $null

    $callback = [WinHelper+EnumWindowsProc]{
        param($hWnd, $lParam)
        if (-not [WinHelper]::IsWindowVisible($hWnd)) { return $true }
        $winPid = 0
        [WinHelper]::GetWindowThreadProcessId($hWnd, [ref]$winPid) | Out-Null
        if ($firefoxPIDs -contains $winPid) {
            $sb = New-Object System.Text.StringBuilder 512
            [WinHelper]::GetWindowText($hWnd, $sb, 512) | Out-Null
            $title = $sb.ToString()
            if ($title -like "*Private Browsing*" -and $title -like "*Mozilla Firefox*") {
                $script:privateHandle = $hWnd
                return $false
            }
        }
        return $true
    }
    $script:privateHandle = $null
    [WinHelper]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
    return $script:privateHandle
}

# Read ALL visible text from a window via UI Automation
function Get-WindowVisibleText {
    param([IntPtr]$hWnd)
    try {
        $uiAuto  = [System.Windows.Automation.AutomationElement]
        $element = $uiAuto::FromHandle($hWnd)
        if ($null -eq $element) { return "" }

        $condition   = [System.Windows.Automation.Condition]::TrueCondition
        $allElements = $element.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            $condition
        )

        $texts = [System.Collections.Generic.List[string]]::new()
        foreach ($el in $allElements) {
            try {
                $name = $el.GetCurrentPropertyValue(
                    [System.Windows.Automation.AutomationElement]::NameProperty)
                if ($name -and $name.ToString().Trim() -ne "") {
                    $texts.Add($name.ToString().Trim())
                }
            } catch { }
        }
        return ($texts -join " ")
    } catch {
        return ""
    }
}

# Check keywords anywhere in the page text
function Test-IncidentInText {
    param([string]$Text)
    $upper = $Text.ToUpper()
    foreach ($kw in $IncidentKeywords) {
        if ($upper.Contains($kw.ToUpper())) {
            return $kw
        }
    }
    return $null
}

# Alert - double beep + red banner
function Invoke-IncidentAlert {
    param([string]$MatchedKeyword)
    [System.Media.SystemSounds]::Exclamation.Play()
    Start-Sleep -Milliseconds 600
    [System.Media.SystemSounds]::Exclamation.Play()
    Write-Host ""
    Write-Host "  ############################################" -ForegroundColor Red
    Write-Host "  ###  INCIDENT DETECTED ON SNOW PAGE      ###" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ###  Keyword found : $MatchedKeyword       " -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ###  Time          : $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Red -BackgroundColor Black
    Write-Host "  ############################################" -ForegroundColor Red
    Write-Host ""
}

# Startup banner
Write-Host ""
Write-Host "  AutoF5-Snow is running." -ForegroundColor White
Write-Host "  Refreshes Firefox Private window every $IntervalSeconds seconds." -ForegroundColor White
Write-Host "  Reads ALL visible page text via UI Automation after each refresh." -ForegroundColor White
Write-Host "  Alert triggers if page contains: $($IncidentKeywords -join ' | ')" -ForegroundColor Yellow
Write-Host "  Press Ctrl+C to stop." -ForegroundColor White
Write-Host ""

$count = 0

while ($true) {
    $nextTime = (Get-Date).AddSeconds($IntervalSeconds).ToString("HH:mm:ss")
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Waiting $IntervalSeconds s... next check at $nextTime"

    Start-Sleep -Seconds $IntervalSeconds

    $privateHwnd = Get-FirefoxPrivateWindowHandle

    if ($null -ne $privateHwnd) {

        $wasMinimized = [WinHelper]::IsIconic($privateHwnd)

        # Always restore before scanning - UI Automation needs window visible
        if ($wasMinimized) {
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Restoring minimized window..." -ForegroundColor Cyan
            [WinHelper]::ShowWindow($privateHwnd, [WinHelper]::SW_RESTORE) | Out-Null
            Start-Sleep -Milliseconds 600
        }

        [WinHelper]::SetForegroundWindow($privateHwnd) | Out-Null
        Start-Sleep -Milliseconds 300
        [WinHelper]::PressF5()

        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  F5 sent - waiting for page to load..." -ForegroundColor Gray

        # 2 seconds for ServiceNow to finish rendering
        Start-Sleep -Milliseconds 2000

        # Read all visible text from the browser window
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Scanning page content via UI Automation..." -ForegroundColor Gray
        $pageText = Get-WindowVisibleText -hWnd $privateHwnd

        $matched = Test-IncidentInText -Text $pageText

        if ($null -ne $matched) {
            Invoke-IncidentAlert -MatchedKeyword $matched
        } else {
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  No incident keywords found on page." -ForegroundColor DarkGray
        }

        # Re-minimize if it was minimized before
        if ($wasMinimized) {
            Start-Sleep -Milliseconds 400
            [WinHelper]::ShowWindow($privateHwnd, [WinHelper]::SW_MINIMIZE) | Out-Null
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Window re-minimized." -ForegroundColor Cyan
        }

        $count++
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Cycle $count complete." -ForegroundColor Green

    } else {
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  No Firefox Private window found - skipped." -ForegroundColor Yellow
    }
}