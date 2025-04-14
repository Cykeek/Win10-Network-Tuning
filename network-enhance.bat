@echo off
chcp 65001 >nul
color 0A

:: ================= HEADER ===================
echo.
echo ==================================================
echo   Optimizing Windows Network Performance...
echo ==================================================
echo.

:: ============ BACKUP CURRENT SETTINGS ============
echo Backing up current TCP registry settings...
start /b "" cmd /c "reg export \"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" \"C:\TCPSettingsBackup.reg\" >nul 2>&1 && echo [✓] Backup saved to C:\TCPSettingsBackup.reg"
timeout /t 5 >nul
if not exist "C:\TCPSettingsBackup.reg" (
    echo [✗] Backup may have failed or is taking too long. Please ensure admin rights.
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
echo [✓] TCP Registry tweaks applied.

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
echo [✓] DNS cache parameters optimized.

:: ============ DISABLE SMB SIGNING ============
echo.
echo Disabling SMB packet signing for performance...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 0 /f >nul
echo [✓] SMB packet signing disabled.

:: ============ PRIORITIZE IPV4 ============
echo.
echo Prioritizing IPv4 over IPv6...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 32 /f >nul
echo [✓] IPv4 is now prioritized over IPv6.

:: ============ DISABLE DELIVERY OPTIMIZATION ============
echo.
echo Disabling Windows Update Delivery Optimization...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
echo [✓] Delivery Optimization disabled.

:: ============ FLUSH DNS AND RESET NETWORK STACK ============
echo.
echo Flushing DNS and resetting network stack...
ipconfig /flushdns >nul
netsh int ip reset >nul
netsh winsock reset >nul
echo [✓] Network stack and DNS cache reset.

:: ============ DONE ============
echo.
echo ✓ All network optimizations applied. Please restart your computer to finalize the changes.
pause >nul
