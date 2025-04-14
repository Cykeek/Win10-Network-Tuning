@echo off
chcp 65001 >nul
color 0A

:: Check for Administrator privileges
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo This script requires Administrator privileges.
    echo Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

:: ================= HEADER ===================
echo.
echo ==================================================
echo   Optimizing Windows Network Performance...
echo ==================================================
echo.

:: ============ BACKUP CURRENT SETTINGS ============
echo Creating backup of current network settings...
set "BACKUP_PATH=%USERPROFILE%\Desktop\NetworkSettingsBackup_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.reg"
set "BACKUP_PATH=%BACKUP_PATH: =0%"

echo Backing up TCP/IP settings to: %BACKUP_PATH%
reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "%BACKUP_PATH%" /y >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Network settings backup created successfully at:
    echo      %BACKUP_PATH%
) else (
    echo [ERROR] Failed to create backup. Continuing without backup...
    echo Press Ctrl+C to cancel or any key to continue...
    pause >nul
)

:: ============ APPLY REGISTRY TWEAKS ============
echo.
echo Applying TCP Registry Tweaks...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Tcp1323Opts /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableTCPChimney /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableRSS /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableTCPA /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SackOpts /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpWindowSize /t REG_DWORD /d 64240 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DefaultTTL /t REG_DWORD /d 64 /f >nul
echo [OK] TCP Registry tweaks applied.

:: ============ APPLY NETSH TWEAKS ============
echo.
echo Applying Netsh TCP Tweaks...
netsh int tcp set global autotuninglevel=normal >nul
echo Ok.
netsh int tcp set global rss=enabled >nul
echo Ok.
netsh int tcp set global ecncapability=enabled >nul
echo Ok.
netsh int tcp set global timestamps=disabled >nul
echo Ok.
netsh int tcp set global initialrto=3000 >nul
echo Ok.
netsh int tcp set global rsc=enabled >nul
echo Ok.
netsh int tcp set global nonsackrttresiliency=disabled >nul
echo Ok.
netsh int tcp set global maxsynretransmissions=2 >nul
echo Ok.
netsh int tcp set global fastopen=enabled >nul
echo Ok.
netsh int tcp set global hystart=enabled >nul
echo Ok.
netsh int tcp set global prr=enabled >nul
echo Ok.
netsh int tcp set global pacingprofile=always >nul
echo Ok.

:: ============ DNS CACHE OPTIMIZATION ============
echo.
echo Optimizing DNS cache size...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableBucketSize /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableSize /t REG_DWORD /d 384 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheEntryTtlLimit /t REG_DWORD /d 64000 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxSOACacheEntryTtlLimit /t REG_DWORD /d 300 /f >nul
echo [OK] DNS cache parameters optimized.

:: ============ DISABLE SMB SIGNING ============
echo.
echo Disabling SMB packet signing for performance...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f >nul
echo [OK] SMB packet signing disabled.

:: ============ PRIORITIZE IPV4 ============
echo.
echo Prioritizing IPv4 over IPv6...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 32 /f >nul
echo [OK] IPv4 is now prioritized over IPv6.

:: ============ DISABLE DELIVERY OPTIMIZATION ============
echo.
echo Disabling Windows Update Delivery Optimization...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
echo [OK] Delivery Optimization disabled.

:: ============ QOS OPTIMIZATION ============
echo.
echo Optimizing Quality of Service settings...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
echo [OK] QoS settings optimized.

:: ============ NETWORK ADAPTER POWER SETTINGS ============
echo.
echo Optimizing network adapter power settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v PnPCapabilities /t REG_DWORD /d 24 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v *PowerSaving /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v *SelectiveSuspend /t REG_DWORD /d 0 /f >nul
echo [OK] Network adapter power settings optimized.

:: ============ SYSTEM NETWORK SETTINGS ============
echo.
echo Optimizing system network settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultReceiveWindow /t REG_DWORD /d 64240 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultSendWindow /t REG_DWORD /d 64240 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxUserPort /t REG_DWORD /d 65534 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpTimedWaitDelay /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v MaxFreeTcbs /t REG_DWORD /d 65535 /f >nul
echo [OK] System network settings optimized.

:: ============ ADDITIONAL TCP OPTIMIZATIONS ============
echo.
echo Applying additional TCP optimizations...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 300000 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveInterval /t REG_DWORD /d 1000 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 5 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectRetransmissions /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpNumConnections /t REG_DWORD /d 16777214 /f >nul
echo [OK] Additional TCP optimizations applied.

:: ============ NETWORK INTERFACE SETTINGS ============
echo.
echo Optimizing network interface settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v MTU /t REG_DWORD /d 1500 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUDiscovery /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnablePMTUBHDetect /t REG_DWORD /d 0 /f >nul
echo [OK] Network interface settings optimized.

:: ============ FLUSH DNS AND RESET NETWORK STACK ============
echo.
echo Flushing DNS and resetting network stack...
ipconfig /flushdns >nul
netsh int ip reset >nul
netsh winsock reset >nul
echo [OK] Network stack and DNS cache reset.

:: ============ DONE ============
echo.
echo [OK] All network optimizations applied. Please restart your computer to finalize the changes.
pause >nul
