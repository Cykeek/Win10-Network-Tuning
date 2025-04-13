@echo off
:: Run as administrator check
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit /b
)

echo.
echo Backing up current TCP registry settings...
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "%SystemDrive%\TCPSettingsBackup.reg" /y >nul
echo [INFO] Backup saved to %SystemDrive%\TCPSettingsBackup.reg

echo.
echo Applying TCP Registry Tweaks...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Tcp1323Opts /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpWindowSize /t REG_DWORD /d 64240 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v GlobalMaxTcpWindowSize /t REG_DWORD /d 64240 /f >nul
echo [INFO] TCP Registry tweaks applied.

echo.
echo Applying Netsh TCP Tweaks...
netsh int tcp set global autotuninglevel=normal >nul
netsh int tcp set global ecncapability=enabled >nul
netsh int tcp set global rss=disabled >nul
netsh int tcp set global netdma=disabled >nul
echo [INFO] Netsh TCP tweaks applied.

echo.
echo Optimizing DNS cache size...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableBucketSize /t REG_DWORD /d 384 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableSize /t REG_DWORD /d 512 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheEntryTtlLimit /t REG_DWORD /d 86400 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxSOACacheEntryTtlLimit /t REG_DWORD /d 300 /f >nul
echo [INFO] DNS cache parameters optimized.

echo.
echo Disabling SMB packet signing for performance...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 0 /f >nul
echo [INFO] SMB packet signing disabled.

echo.
echo Prioritizing IPv4 over IPv6...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 32 /f >nul
echo [INFO] IPv4 is now prioritized over IPv6.

echo.
echo Disabling Windows Update Delivery Optimization...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
echo [INFO] Delivery Optimization disabled.

echo.
echo Flushing DNS and resetting network stack...
ipconfig /flushdns >nul
netsh int ip reset >nul
echo [INFO] Network stack and DNS cache reset.

echo.
echo [INFO] All network optimizations applied. Please restart your computer to finalize the changes.
pause
