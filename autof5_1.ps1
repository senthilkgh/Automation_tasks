# ============================================================
#  AutoF5.ps1 - Simulates F5 keypress every 5 minutes
#  Fires F5 on Firefox Private Browsing window if one exists
#  Works even if the private window is minimized
#  Stop anytime with: Ctrl+C
# ============================================================

$IntervalSeconds = 60

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

function Get-FirefoxPrivateWindowHandle {
    $firefoxProcs = Get-Process -Name "firefox" -ErrorAction SilentlyContinue
    if ($firefoxProcs -eq $null -or $firefoxProcs.Count -eq 0) {
        return $null
    }

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

Write-Host ""
Write-Host "  AutoF5 is running. Checks every $IntervalSeconds seconds."
Write-Host "  F5 fires on the Private window whenever one exists."
Write-Host "  Works even if the Private window is minimized."
Write-Host "  Press Ctrl+C to stop."
Write-Host ""

$count = 0

while ($true) {
    $nextTime = (Get-Date).AddSeconds($IntervalSeconds).ToString("HH:mm:ss")
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Waiting $IntervalSeconds s... next check at $nextTime"

    Start-Sleep -Seconds $IntervalSeconds

    $privateHwnd = Get-FirefoxPrivateWindowHandle

    if ($privateHwnd -ne $null) {

        # Check if the window is minimized
        $wasMinimized = [WinHelper]::IsIconic($privateHwnd)

        if ($wasMinimized) {
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Window is minimized - restoring..." -ForegroundColor Cyan
            [WinHelper]::ShowWindow($privateHwnd, [WinHelper]::SW_RESTORE) | Out-Null
            Start-Sleep -Milliseconds 500
        }

        # Bring to foreground and send F5
        [WinHelper]::SetForegroundWindow($privateHwnd) | Out-Null
        Start-Sleep -Milliseconds 300
        [WinHelper]::PressF5()

        # If it was minimized before, minimize it again after F5
        if ($wasMinimized) {
            Start-Sleep -Milliseconds 500
            [WinHelper]::ShowWindow($privateHwnd, [WinHelper]::SW_MINIMIZE) | Out-Null
            Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Window re-minimized after F5" -ForegroundColor Cyan
        }

        $count++
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  Private window found - F5 pressed (total: $count)" -ForegroundColor Green

    } else {
        Write-Host "  [$(Get-Date -Format 'HH:mm:ss')]  No Private window found - F5 skipped" -ForegroundColor Yellow
    }
}