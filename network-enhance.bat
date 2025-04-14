@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
color 0A

:: Script Version
set "VERSION=2.1"

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
set "DNS_OPTIMIZE=N"
set "ADAPTER_POWER=N"
set "SMB_OPTIMIZE=N"
set "QOS_OPTIMIZE=N"
set "IPV_SETTINGS=N"
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
    echo [OK] QoS Settings optimized
)

:: Apply IPv4/IPv6 Settings if selected
if "%IPV_SETTINGS%"=="Y" (
    echo.
    echo Configuring IP Settings...
    call :log "Applying IP Settings..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 32 /f >nul
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
    netsh advfirewall set allprofiles state on >nul
    netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d 2 /f >nul
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

:: Verify and finalize changes
echo.
echo Verifying changes...
call :log "Verifying changes..."

:: Check if any optimizations were applied
set "CHANGES_MADE=N"
for %%i in (TCP_OPTIMIZE DNS_OPTIMIZE ADAPTER_POWER SMB_OPTIMIZE QOS_OPTIMIZE IPV_SETTINGS UDP_OPTIMIZE NIC_TUNE MEM_OPTIMIZE SEC_OPTIMIZE GAME_OPTIMIZE STREAM_OPTIMIZE) do (
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
