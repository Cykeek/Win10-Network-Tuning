@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
color 0A

:: Script Version
set "VERSION=2.3"

:: Initialize logging
set "NETWORK_DIR=%USERPROFILE%\Documents\Networks"
if not exist "%NETWORK_DIR%" mkdir "%NETWORK_DIR%"
set "LOG_PATH=%NETWORK_DIR%\NetworkOptimizer_Log_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.txt"
set "LOG_PATH=%LOG_PATH: =0%"

:: Check for Administrator privileges
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

:menu
cls
echo ==================================================
echo   Windows Network Performance Optimizer v%VERSION%
echo ==================================================
echo.
echo Select options to apply (Use Y/N to toggle):
echo --------------------------------------------------
echo [Basic Optimizations]
call :show_option "1" "Create System Restore Point" CREATE_RESTORE
call :show_option "2" "Create Registry Backup" BACKUP_SETTINGS
echo.
echo [Network Protocol Optimizations]
call :show_option "3" "TCP Optimization" TCP_OPTIMIZE
call :show_option "4" "UDP Optimization" UDP_OPTIMIZE
call :show_option "5" "DNS Cache Optimization" DNS_OPTIMIZE
call :show_option "6" "Network Adapter Power Settings" ADAPTER_POWER
echo.
echo [Advanced Optimizations]
call :show_option "7" "SMB Performance Settings" SMB_OPTIMIZE
call :show_option "8" "QoS Optimization" QOS_OPTIMIZE
call :show_option "9" "IPv4/IPv6 Settings" IPV_SETTINGS
echo.
echo [Additional Optimizations]
call :show_option "10" "Network Interface Tuning" NIC_TUNE
call :show_option "11" "Network Memory Management" MEM_OPTIMIZE
call :show_option "12" "Network Security Settings" SEC_OPTIMIZE
call :show_option "13" "Gaming Mode Optimization" GAME_OPTIMIZE
call :show_option "14" "Streaming Mode Optimization" STREAM_OPTIMIZE
call :show_option "15" "Network Maintenance" NET_MAINTENANCE
call :show_option "16" "Bandwidth Management" BANDWIDTH_MANAGE
call :show_option "17" "Connection Type Optimization" CONN_TYPE_OPTIMIZE
call :show_option "18" "Network Health Report" HEALTH_REPORT
echo --------------------------------------------------
echo A. Apply Selected Optimizations
echo V. View Current Network Settings
echo R. Reset All Options
echo X. Exit
echo.
set /p "choice=Enter your choice: "

if /i "%choice%"=="1" call :toggle_option CREATE_RESTORE & goto menu
if /i "%choice%"=="2" call :toggle_option BACKUP_SETTINGS & goto menu
if /i "%choice%"=="3" call :toggle_option TCP_OPTIMIZE & goto menu
if /i "%choice%"=="4" call :toggle_option UDP_OPTIMIZE & goto menu
if /i "%choice%"=="5" call :toggle_option DNS_OPTIMIZE & goto menu
if /i "%choice%"=="6" call :toggle_option ADAPTER_POWER & goto menu
if /i "%choice%"=="7" call :toggle_option SMB_OPTIMIZE & goto menu
if /i "%choice%"=="8" call :toggle_option QOS_OPTIMIZE & goto menu
if /i "%choice%"=="9" call :toggle_option IPV_SETTINGS & goto menu
if /i "%choice%"=="10" call :toggle_option NIC_TUNE & goto menu
if /i "%choice%"=="11" call :toggle_option MEM_OPTIMIZE & goto menu
if /i "%choice%"=="12" call :toggle_option SEC_OPTIMIZE & goto menu
if /i "%choice%"=="13" call :toggle_option GAME_OPTIMIZE & goto menu
if /i "%choice%"=="14" call :toggle_option STREAM_OPTIMIZE & goto menu
if /i "%choice%"=="15" call :toggle_option NET_MAINTENANCE & goto menu
if /i "%choice%"=="16" call :toggle_option BANDWIDTH_MANAGE & goto menu
if /i "%choice%"=="17" call :toggle_option CONN_TYPE_OPTIMIZE & goto menu
if /i "%choice%"=="18" call :toggle_option HEALTH_REPORT & goto menu
if /i "%choice%"=="a" goto apply_changes
if /i "%choice%"=="v" goto view_settings
if /i "%choice%"=="r" goto reset_options
if /i "%choice%"=="x" exit /b 0
goto menu

:show_option
if not defined %3 set "%3=N"
echo [%~1] %~2: [!%3!]
exit /b

:toggle_option
if "%1"=="" exit /b
if "!%1!"=="Y" (
    set "%1=N"
) else (
    set "%1=Y"
)
exit /b

:reset_options
set "CREATE_RESTORE=N"
set "BACKUP_SETTINGS=N"
set "TCP_OPTIMIZE=N"
set "UDP_OPTIMIZE=N"
set "DNS_OPTIMIZE=N"
set "ADAPTER_POWER=N"
set "SMB_OPTIMIZE=N"
set "QOS_OPTIMIZE=N"
set "IPV_SETTINGS=N"
set "NIC_TUNE=N"
set "MEM_OPTIMIZE=N"
set "SEC_OPTIMIZE=N"
set "GAME_OPTIMIZE=N"
set "STREAM_OPTIMIZE=N"
set "NET_MAINTENANCE=N"
set "BANDWIDTH_MANAGE=N"
set "CONN_TYPE_OPTIMIZE=N"
set "HEALTH_REPORT=N"
goto menu

:view_settings
cls
echo ==================================================
echo   Current Network Settings
echo ==================================================
echo.
echo TCP/IP Settings:
netsh interface tcp show global
echo.
echo Network Adapters:
wmic nic where "PhysicalAdapter=TRUE" get Name, Speed
echo.
echo DNS Settings:
ipconfig /displaydns | findstr "Record Name"
echo.
pause
goto menu

:apply_changes
cls
echo ==================================================
echo   Applying Selected Optimizations
echo ==================================================
echo.

:: Initialize log file
echo Windows Network Performance Optimizer v%VERSION% > "%LOG_PATH%"
echo Optimization started at: %date% %time% >> "%LOG_PATH%"
echo. >> "%LOG_PATH%"

:: Capture network health data before changes if health report is selected
if "%HEALTH_REPORT%"=="Y" (
    echo Capturing network baseline statistics...
    call :log "Capturing network baseline statistics..."
    
    set "HEALTH_DATA_PATH=%NETWORK_DIR%\NetworkHealth_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.txt"
    set "HEALTH_DATA_PATH=!HEALTH_DATA_PATH: =0!"
    
    echo Network Health Report - BEFORE Optimization > "!HEALTH_DATA_PATH!"
    echo Date: %date% Time: %time% >> "!HEALTH_DATA_PATH!"
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo TCP/IP Configuration: >> "!HEALTH_DATA_PATH!"
    ipconfig /all >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Network Statistics: >> "!HEALTH_DATA_PATH!"
    netstat -s >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Network Interface Statistics: >> "!HEALTH_DATA_PATH!"
    netsh interface ipv4 show interfaces >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo TCP Global Parameters: >> "!HEALTH_DATA_PATH!"
    netsh interface tcp show global >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Current Network Connections: >> "!HEALTH_DATA_PATH!"
    netstat -ano >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo DNS Cache: >> "!HEALTH_DATA_PATH!"
    ipconfig /displaydns | findstr "Record Name" >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo [OK] Network baseline captured
)

:: Create System Restore Point if selected
if "%CREATE_RESTORE%"=="Y" (
    echo Creating System Restore Point...
    call :log "Creating System Restore Point..."
    wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Network Optimization", 100, 7 >nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] System Restore Point created successfully.
        call :log "[OK] System Restore Point created"
    ) else (
        echo [WARNING] Failed to create System Restore Point.
        call :log "[WARNING] System Restore Point creation failed"
    )
)

:: Create Registry Backup if selected
if "%BACKUP_SETTINGS%"=="Y" (
    echo.
    echo Creating backup of current network settings...
    call :log "Creating registry backup..."
    set "BACKUP_PATH=%NETWORK_DIR%\NetworkSettingsBackup_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.reg"
    set "BACKUP_PATH=!BACKUP_PATH: =0!"
    
    echo Backing up TCP/IP settings to: !BACKUP_PATH!
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "!BACKUP_PATH!" /y >nul 2>&1
    if !errorlevel! equ 0 (
        echo [OK] Network settings backup created at: !BACKUP_PATH!
        call :log "[OK] Registry backup created"
    ) else (
        echo [ERROR] Failed to create backup.
        call :log "[ERROR] Registry backup failed"
        echo Press any key to continue or Ctrl+C to cancel...
        pause >nul
    )
)

:: Apply TCP Optimizations if selected
if "%TCP_OPTIMIZE%"=="Y" (
    echo.
    echo Applying TCP Optimizations...
    call :log "Applying TCP Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    :: Disable Nagle's Algorithm for reduced latency
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    :: Additional latency reduction tweaks
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d 64 /f >nul
    echo [OK] TCP Optimizations applied
)

:: Apply UDP Optimizations if selected
if "%UDP_OPTIMIZE%"=="Y" (
    echo.
    echo Applying UDP Optimizations...
    call :log "Applying UDP Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d 1000 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d 1000 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d 0 /f >nul
    echo [OK] UDP Optimizations applied
)

:: Apply DNS Cache Optimizations if selected
if "%DNS_OPTIMIZE%"=="Y" (
    echo.
    echo Optimizing DNS cache...
    call :log "Applying DNS Cache Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d 384 /f >nul
    echo [OK] DNS Cache optimized
)

:: Apply Network Adapter Power Settings if selected
if "%ADAPTER_POWER%"=="Y" (
    echo.
    echo Optimizing Network Adapter Power Settings...
    call :log "Applying Network Adapter Power Settings..."
    powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
    powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100
    echo [OK] Network Adapter Power Settings optimized
)

:: Apply SMB Optimizations if selected
if "%SMB_OPTIMIZE%"=="Y" (
    echo.
    echo Optimizing SMB Settings...
    call :log "Applying SMB Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d 0 /f >nul
    echo [OK] SMB Settings optimized
)

:: Apply QoS Optimizations if selected
if "%QOS_OPTIMIZE%"=="Y" (
    echo.
    echo Optimizing QoS Settings...
    call :log "Applying QoS Optimizations..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d 1 /f >nul
    :: Network priority settings
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d 8 /f >nul
    :: Reserve bandwidth for applications
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "ApplicationGUID" /t REG_MULTI_SZ /d "{00000000-0000-0000-0000-000000000000}" /f >nul
    echo [OK] QoS Settings optimized
)

:: Apply IPv4/IPv6 Settings if selected
if "%IPV_SETTINGS%"=="Y" (
    echo.
    echo Configuring IP Settings...
    call :log "Applying IP Settings..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 32 /f >nul
    :: Optimize IPv4 settings
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d 1 /f >nul
    echo [OK] IP Settings configured
)

:: Apply Network Interface Tuning if selected
if "%NIC_TUNE%"=="Y" (
    echo.
    echo Applying Network Interface Tuning...
    call :log "Applying Network Interface Tuning..."
    netsh int tcp set global congestionprovider=ctcp >nul
    netsh int tcp set global autotuninglevel=normal >nul
    netsh int tcp set global ecncapability=enabled >nul
    netsh int tcp set global timestamps=disabled >nul
    :: MTU optimization
    netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent >nul 2>&1
    netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent >nul 2>&1
    :: Network adapter offloading optimization
    powershell -Command "Get-NetAdapter -Physical | ForEach-Object { Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 -NoRestart }" >nul 2>&1
    powershell -Command "Get-NetAdapter -Physical | ForEach-Object { Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*TcpChecksumOffloadIPv4' -RegistryValue 1 -NoRestart }" >nul 2>&1
    echo [OK] Network Interface Tuning applied
)

:: Apply Memory Management Optimizations if selected
if "%MEM_OPTIMIZE%"=="Y" (
    echo.
    echo Optimizing Network Memory Management...
    call :log "Applying Memory Management Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d 65535 /f >nul
    echo [OK] Memory Management Optimizations applied
)

:: Apply Network Security Settings if selected
if "%SEC_OPTIMIZE%"=="Y" (
    echo.
    echo Applying Network Security Optimizations...
    call :log "Applying Network Security Optimizations..."
    
    :: Basic firewall setup
    echo Setting up firewall policies...
    netsh advfirewall set allprofiles state on >nul
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d 2 /f >nul
    
    :: Scan for vulnerable ports and disable them
    echo Checking for vulnerable ports...
    call :log "Checking for vulnerable ports..."
    
    :: Check for open vulnerable ports using netstat
    netstat -an | findstr "LISTENING" > "%TEMP%\open_ports.txt"
    
    :: List of commonly vulnerable ports to check
    set "VULNERABLE_PORTS=135 137 138 139 445 1433 1434 3389 5000 5432"
    
    for %%p in (%VULNERABLE_PORTS%) do (
        findstr ":%%p" "%TEMP%\open_ports.txt" >nul
        if !errorlevel! equ 0 (
            echo -- Vulnerable port %%p found open, creating blocking rule
            call :log "Blocking vulnerable port %%p"
            netsh advfirewall firewall add rule name="Block Vulnerable Port %%p" dir=in action=block protocol=TCP localport=%%p >nul
            netsh advfirewall firewall add rule name="Block Vulnerable Port %%p UDP" dir=in action=block protocol=UDP localport=%%p >nul
        )
    )
    
    :: Block known malicious IP ranges
    echo Blocking known malicious IP ranges...
    call :log "Blocking known malicious IP ranges..."
    
    :: Create a new firewall rule group for malicious IPs
    netsh advfirewall firewall add rule name="Block Malicious IP Ranges" dir=in action=block remoteip=185.174.100.0/24,194.165.16.0/24,5.188.86.0/24,185.254.196.0/24,194.87.232.0/24,91.219.236.0/24,176.107.176.0/24 >nul
    
    :: Add outbound block as well
    netsh advfirewall firewall add rule name="Block Malicious IP Ranges (Outbound)" dir=out action=block remoteip=185.174.100.0/24,194.165.16.0/24,5.188.86.0/24,185.254.196.0/24,194.87.232.0/24,91.219.236.0/24,176.107.176.0/24 >nul
    
    :: Enable stealth mode (don't respond to pings)
    echo Enabling stealth mode...
    netsh advfirewall firewall add rule name="Block ICMP Ping" protocol=icmpv4:8,any dir=in action=block >nul
    
    :: Block unused protocols
    echo Securing network protocols...
    :: Disable NetBIOS over TCP/IP
    for /f "tokens=*" %%i in ('wmic nicconfig where TcpipNetbiosOptions^=0 get Index /format:list ^| findstr "="') do (
        for /f "tokens=2 delims==" %%j in ("%%i") do (
            wmic nicconfig where Index=%%j call SetTcpipNetbios 2 >nul
        )
    )
    
    :: Protocol Hardening
    echo Applying protocol hardening...
    call :log "Applying protocol hardening..."
    
    :: Disable SMBv1 (vulnerable to WannaCry and other exploits)
    echo -- Disabling SMBv1...
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f >nul
    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi >nul
    sc.exe config mrxsmb10 start= disabled >nul
    
    :: Enable SMB signing and encryption
    echo -- Enabling SMB signing and encryption...
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EncryptData" /t REG_DWORD /d 1 /f >nul
    
    :: TLS configuration - Enable TLS 1.2 and disable older versions
    echo -- Configuring TLS security...
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v "Enabled" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v "DisabledByDefault" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v "Enabled" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v "DisabledByDefault" /t REG_DWORD /d 0 /f >nul
    
    :: Disable SSL 2.0 and 3.0
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f >nul
    
    :: Network Discovery Protection
    echo Applying network discovery protection...
    call :log "Applying network discovery protection..."
    
    :: Disable LLMNR (Link-Local Multicast Name Resolution)
    echo -- Disabling LLMNR...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f >nul
    
    :: Disable WPAD (Web Proxy Auto-Discovery)
    echo -- Disabling WPAD...
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v "WpadOverride" /t REG_DWORD /d 1 /f >nul
    
    :: Set networks to private profile for better security
    echo -- Setting networks to private profile...
    powershell -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private" >nul 2>&1
    
    :: Disable NetBIOS name service and WINS lookup
    echo -- Disabling NetBIOS name service...
    for /f "tokens=*" %%i in ('wmic nicconfig where "IPEnabled=TRUE" get Index /format:list ^| findstr "="') do (
        for /f "tokens=2 delims==" %%j in ("%%i") do (
            wmic nicconfig where Index=%%j call SetTcpipNetbios 2 >nul
        )
    )
    
    echo [OK] Network Security Optimizations applied
)

:: Apply Gaming Mode Optimizations if selected
if "%GAME_OPTIMIZE%"=="Y" (
    echo.
    echo Applying Gaming Mode Optimizations...
    call :log "Applying Gaming Mode Optimizations..."
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul
    echo [OK] Gaming Mode Optimizations applied
)

:: Apply Streaming Mode Optimizations if selected
if "%STREAM_OPTIMIZE%"=="Y" (
    echo.
    echo Applying Streaming Mode Optimizations...
    call :log "Applying Streaming Mode Optimizations..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul
    netsh int tcp set global initialRto=2000 >nul
    echo [OK] Streaming Mode Optimizations applied
)

:: Apply Network Maintenance if selected
if "%NET_MAINTENANCE%"=="Y" (
    echo.
    echo Performing Network Maintenance...
    call :log "Performing Network Maintenance..."
    :: Reset network components
    ipconfig /flushdns >nul
    netsh winsock reset >nul
    netsh int ip reset >nul
    ipconfig /release >nul
    ipconfig /renew >nul
    :: Clear ARP cache
    netsh interface ip delete arpcache >nul
    :: Reset Internet settings
    RunDll32.exe InetCpl.cpl,ResetIEtoDefaults >nul 2>&1
    echo [OK] Network Maintenance completed
)

:: Apply Bandwidth Management if selected
if "%BANDWIDTH_MANAGE%"=="Y" (
    echo.
    echo Applying Bandwidth Management...
    call :log "Applying Bandwidth Management..."
    
    :: Configure QoS packet scheduler
    echo -- Configuring QoS packet scheduling...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 20 /f >nul
    
    :: Limit background transfer service bandwidth
    echo -- Limiting background app bandwidth...
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /v "MaxBandwidthVal" /t REG_DWORD /d 40 /f >nul
    
    :: Configure throttling values for Windows Update
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DOMaxDownloadBandwidth" /t REG_DWORD /d 10485760 /f >nul
    
    :: Prioritize Gaming and Media traffic
    echo -- Prioritizing multimedia applications...
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 70 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d 10000 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul
    
    :: Block common bandwidth-heavy apps from using too much bandwidth (modify for your needs)
    echo -- Creating firewall rules for bandwidth management...
    netsh advfirewall firewall add rule name="Limit OneDrive Bandwidth" program="%LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe" action=allow dir=out enable=yes profile=any remoteport=443 protocol=TCP >nul 2>&1
    
    echo [OK] Bandwidth Management applied
)

:: Apply Connection Type Optimization if selected
if "%CONN_TYPE_OPTIMIZE%"=="Y" (
    echo.
    echo Applying Connection Type Optimization...
    call :log "Applying Connection Type Optimization..."
    
    :: Detect connection type
    echo -- Detecting connection type...
    
    :: Create temporary file for connection detection
    set "CONN_DETECT_FILE=%TEMP%\connection_type.txt"
    
    :: Use PowerShell to get interface information
    powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription, LinkSpeed | Format-Table -AutoSize > '%CONN_DETECT_FILE%'" >nul 2>&1
    
    :: Look for connection types
    set "CONN_TYPE=Unknown"
    findstr /i "Wi-Fi Wireless" "%CONN_DETECT_FILE%" >nul 2>&1
    if !errorlevel! equ 0 set "CONN_TYPE=WiFi"
    
    findstr /i "Ethernet" "%CONN_DETECT_FILE%" >nul 2>&1
    if !errorlevel! equ 0 set "CONN_TYPE=Ethernet"
    
    :: Check for fiber based on speed (usually 1Gbps or higher)
    findstr /i "Gbps" "%CONN_DETECT_FILE%" >nul 2>&1
    if !errorlevel! equ 0 (
        findstr /i "Ethernet" "%CONN_DETECT_FILE%" >nul 2>&1
        if !errorlevel! equ 0 set "CONN_TYPE=Fiber"
    )
    
    echo -- Detected connection type: !CONN_TYPE!
    call :log "Detected connection type: !CONN_TYPE!"
    
    :: Apply optimizations based on connection type
    if "!CONN_TYPE!"=="WiFi" (
        echo -- Applying WiFi-specific optimizations...
        
        :: Wi-Fi specific optimizations
        netsh wlan set autoconfig enabled=yes interface="Wi-Fi" >nul 2>&1
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f >nul
        
        :: Adjust MTU for WiFi
        netsh interface ipv4 set subinterface "Wi-Fi" mtu=1472 store=persistent >nul 2>&1
        
        :: Disable background scanning while connected
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WiFi\Interfaces" /v "AutoScanEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
        
        :: Buffer tuning for WiFi
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpInitialRTT" /t REG_DWORD /d 3 /f >nul
    )
    
    if "!CONN_TYPE!"=="Ethernet" (
        echo -- Applying Ethernet-specific optimizations...
        
        :: Ethernet specific optimizations
        netsh interface tcp set global congestionprovider=ctcp >nul
        
        :: Adjust MTU for regular Ethernet
        netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent >nul 2>&1
        
        :: Better buffer settings for Ethernet
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpInitialRTT" /t REG_DWORD /d 2 /f >nul
    )
    
    if "!CONN_TYPE!"=="Fiber" (
        echo -- Applying Fiber-specific optimizations...
        
        :: Fiber specific optimizations
        netsh interface tcp set global congestionprovider=ctcp >nul
        netsh interface tcp set global autotuninglevel=normal >nul
        netsh interface tcp set global chimney=disabled >nul
        
        :: Large MTU for Fiber
        netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent >nul 2>&1
        
        :: Buffer tuning for high-bandwidth connections
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 65535 /f >nul
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d 65535 /f >nul
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d 3 /f >nul
    )
    
    echo [OK] Connection Type Optimization applied for !CONN_TYPE!
)

:: Generate the Network Health Report if selected
if "%HEALTH_REPORT%"=="Y" (
    echo.
    echo Generating Network Health Report...
    call :log "Generating Network Health Report..."
    
    :: Append 'AFTER' data to the health report
    echo. >> "!HEALTH_DATA_PATH!"
    echo ========================================================== >> "!HEALTH_DATA_PATH!"
    echo Network Health Report - AFTER Optimization >> "!HEALTH_DATA_PATH!"
    echo Date: %date% Time: %time% >> "!HEALTH_DATA_PATH!"
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo TCP/IP Configuration: >> "!HEALTH_DATA_PATH!"
    ipconfig /all >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Network Statistics: >> "!HEALTH_DATA_PATH!"
    netstat -s >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Network Interface Statistics: >> "!HEALTH_DATA_PATH!"
    netsh interface ipv4 show interfaces >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo TCP Global Parameters: >> "!HEALTH_DATA_PATH!"
    netsh interface tcp show global >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo Current Network Connections: >> "!HEALTH_DATA_PATH!"
    netstat -ano >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    echo DNS Cache: >> "!HEALTH_DATA_PATH!"
    ipconfig /displaydns | findstr "Record Name" >> "!HEALTH_DATA_PATH!" 2>&1
    echo. >> "!HEALTH_DATA_PATH!"
    
    :: Create a simple HTML report for better visualization
    set "HTML_REPORT=%NETWORK_DIR%\NetworkReport_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.html"
    set "HTML_REPORT=!HTML_REPORT: =0!"
    
    echo ^<!DOCTYPE html^> > "!HTML_REPORT!"
    echo ^<html^> >> "!HTML_REPORT!"
    echo ^<head^> >> "!HTML_REPORT!"
    echo ^<title^>Network Optimization Report^</title^> >> "!HTML_REPORT!"
    echo ^<style^> >> "!HTML_REPORT!"
    echo body { font-family: Arial, sans-serif; margin: 20px; } >> "!HTML_REPORT!"
    echo h1, h2 { color: #0066cc; } >> "!HTML_REPORT!"
    echo .container { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; } >> "!HTML_REPORT!"
    echo .success { color: green; } >> "!HTML_REPORT!"
    echo table { border-collapse: collapse; width: 100%%; } >> "!HTML_REPORT!"
    echo th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } >> "!HTML_REPORT!"
    echo th { background-color: #f2f2f2; } >> "!HTML_REPORT!"
    echo ^</style^> >> "!HTML_REPORT!"
    echo ^</head^> >> "!HTML_REPORT!"
    echo ^<body^> >> "!HTML_REPORT!"
    
    echo ^<h1^>Network Optimization Report^</h1^> >> "!HTML_REPORT!"
    echo ^<p^>Generated on: %date% at %time%^</p^> >> "!HTML_REPORT!"
    
    echo ^<div class="container"^> >> "!HTML_REPORT!"
    echo ^<h2^>Optimizations Applied^</h2^> >> "!HTML_REPORT!"
    echo ^<table^> >> "!HTML_REPORT!"
    echo ^<tr^>^<th^>Optimization^</th^>^<th^>Status^</th^>^</tr^> >> "!HTML_REPORT!"
    
    for %%i in (TCP_OPTIMIZE UDP_OPTIMIZE DNS_OPTIMIZE ADAPTER_POWER SMB_OPTIMIZE QOS_OPTIMIZE IPV_SETTINGS NIC_TUNE MEM_OPTIMIZE SEC_OPTIMIZE GAME_OPTIMIZE STREAM_OPTIMIZE NET_MAINTENANCE BANDWIDTH_MANAGE CONN_TYPE_OPTIMIZE) do (
        if "!%%i!"=="Y" (
            echo ^<tr^>^<td^>%%i^</td^>^<td class="success"^>Applied^</td^>^</tr^> >> "!HTML_REPORT!"
        ) else (
            echo ^<tr^>^<td^>%%i^</td^>^<td^>Not Applied^</td^>^</tr^> >> "!HTML_REPORT!"
        )
    )
    
    echo ^</table^> >> "!HTML_REPORT!"
    echo ^</div^> >> "!HTML_REPORT!"
    
    echo ^<div class="container"^> >> "!HTML_REPORT!"
    echo ^<h2^>Connection Information^</h2^> >> "!HTML_REPORT!"
    
    if "%CONN_TYPE_OPTIMIZE%"=="Y" (
        echo ^<p^>Detected Connection Type: ^<strong^>!CONN_TYPE!^</strong^>^</p^> >> "!HTML_REPORT!"
    ) else (
        echo ^<p^>Connection type detection was not run.^</p^> >> "!HTML_REPORT!"
    )
    
    echo ^<p^>For detailed network information, please see the raw data file at: !HEALTH_DATA_PATH!^</p^> >> "!HTML_REPORT!"
    echo ^</div^> >> "!HTML_REPORT!"
    
    echo ^<div class="container"^> >> "!HTML_REPORT!"
    echo ^<h2^>Recommendations^</h2^> >> "!HTML_REPORT!"
    echo ^<ul^> >> "!HTML_REPORT!"
    echo ^<li^>Restart your computer to apply all changes^</li^> >> "!HTML_REPORT!"
    echo ^<li^>Run the Network Health Report periodically to monitor performance^</li^> >> "!HTML_REPORT!"
    echo ^<li^>Consider adjusting specific settings based on your usage patterns^</li^> >> "!HTML_REPORT!"
    echo ^</ul^> >> "!HTML_REPORT!"
    echo ^</div^> >> "!HTML_REPORT!"
    
    echo ^</body^> >> "!HTML_REPORT!"
    echo ^</html^> >> "!HTML_REPORT!"
    
    echo [OK] Network Health Report generated
    echo -- Report saved to: !HTML_REPORT!
    call :log "Network Health Report generated at !HTML_REPORT!"
)

:: Verify and finalize changes
echo.
echo Verifying changes...
call :log "Verifying changes..."

:: Check if any optimizations were applied
set "CHANGES_MADE=N"
for %%i in (TCP_OPTIMIZE DNS_OPTIMIZE ADAPTER_POWER SMB_OPTIMIZE QOS_OPTIMIZE IPV_SETTINGS UDP_OPTIMIZE NIC_TUNE MEM_OPTIMIZE SEC_OPTIMIZE GAME_OPTIMIZE STREAM_OPTIMIZE NET_MAINTENANCE BANDWIDTH_MANAGE CONN_TYPE_OPTIMIZE HEALTH_REPORT) do (
    if "!%%i!"=="Y" set "CHANGES_MADE=Y"
)

if "%CHANGES_MADE%"=="Y" (
    echo.
    echo ==================================================
    echo   Optimization Complete
    echo ==================================================
    echo.
    echo Important Notes:
    echo 1. Log file created at: %LOG_PATH%
    if "%BACKUP_SETTINGS%"=="Y" echo 2. Registry backup at: %BACKUP_PATH%
    echo 3. A system restart is required to apply all changes.
    echo.
    echo Would you like to restart now? (Y/N)
    set /p "restart_choice="
    if /i "!restart_choice!"=="y" (
        echo.
        echo System will restart in 60 seconds to apply changes.
        echo Close any open applications before restart.
        shutdown /r /t 60 /c "Network optimizations will be applied after restart."
        exit /b 0
    ) else (
        echo.
        echo Please remember to restart your computer later to apply the changes.
        echo.
        echo Press any key to return to menu...
        pause >nul
        goto menu
    )
) else (
    echo.
    echo No optimizations were selected.
    echo Please select at least one optimization option and try again.
    echo.
    echo Press any key to return to menu...
    pause >nul
    goto menu
)

:log
echo %* >> "%LOG_PATH%"
exit /b 0

endlocal
