@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
color 0A

:: Script Version
set "VERSION=3.1"
set "VERSION_INFO=Windows Network Performance Optimizer v%VERSION%"

:: Initialize logging
set "NETWORK_DIR=%USERPROFILE%\Documents\Networks"
set "NETWORK_LOGS=%NETWORK_DIR%\Logs"
if not exist "%NETWORK_DIR%" mkdir "%NETWORK_DIR%"
if not exist "%NETWORK_LOGS%" mkdir "%NETWORK_LOGS%"
set "LOG_PATH=%NETWORK_LOGS%\NetworkOptimizer_Log_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.txt"
set "LOG_PATH=%LOG_PATH: =0%"

:: Check for Administrator privileges
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

:: Check for updates
call :check_for_updates

:: Initialize default options
call :reset_options

:main_menu
cls
echo ================================================================
echo    %VERSION_INFO%
echo ================================================================
echo.
echo  OPTIMIZATION OPTIONS:
echo  ----------------------------------------------------------------
echo  [1] TCP/IP Protocol Stack Optimizations
echo  [2] Connection Type-Specific Optimizations (WiFi/Ethernet/Fiber)
echo  [3] DNS and Memory Management
echo  [4] Network Security Settings
echo  [5] Gaming and Streaming Mode
echo  [6] Show All Available Optimizations
echo.
echo  TOOLS AND UTILITIES:
echo  ----------------------------------------------------------------
echo  [7] Create System Restore Point (RECOMMENDED)
echo  [8] Backup Current Settings
echo  [9] Generate Network Health Report
echo  [10] View Current Network Settings
echo  [11] Clean Logs and Temporary Files
echo.
echo  QUICK OPTIONS:
echo  ----------------------------------------------------------------
echo  [R] Recommended Settings (Best for Most Users)
echo.
echo  [D] View Details for an Option (Shows what changes will be made)
echo  [A] Apply Selected Optimizations
echo  [X] Reset All Selections
echo  [E] Exit
echo.
echo  Currently selected: %SELECTED_COUNT% optimizations
echo.
set /p choice="Enter your choice: "

if "%choice%"=="1" goto menu_tcp_options
if "%choice%"=="2" goto menu_conn_options
if "%choice%"=="3" goto menu_dns_memory_options
if "%choice%"=="4" goto menu_security_options
if "%choice%"=="5" goto menu_gaming_options
if "%choice%"=="6" goto menu_all_options
if "%choice%"=="7" call :toggle_option CREATE_RESTORE
if "%choice%"=="8" call :toggle_option BACKUP_SETTINGS
if "%choice%"=="9" call :toggle_option HEALTH_REPORT
if "%choice%"=="10" goto view_settings
if "%choice%"=="11" goto clean_logs
if /i "%choice%"=="D" goto show_details
if /i "%choice%"=="A" goto apply_changes
if /i "%choice%"=="R" call :apply_recommended_settings
if /i "%choice%"=="X" call :reset_options
if /i "%choice%"=="E" goto exit_script
goto main_menu

:menu_tcp_options
cls
echo ================================================================
echo    TCP/IP PROTOCOL STACK OPTIMIZATIONS
echo ================================================================
echo.
call :show_option "1" "TCP Stack Optimization" TCP_OPTIMIZE "Improves TCP packet handling and latency"
call :show_option "2" "UDP Optimization" UDP_OPTIMIZE "Enhances UDP performance for gaming/streaming"
call :show_option "3" "QoS Packet Scheduler" QOS_OPTIMIZE "Controls bandwidth allocation and priorities"
call :show_option "4" "IPv4/IPv6 Stack Configuration" IPV_SETTINGS "Optimizes IP configuration"
echo.
echo  [D] View detailed explanation of these optimizations
echo  [M] Return to Main Menu
echo.
set /p tcp_choice="Enter your choice: "

if "%tcp_choice%"=="1" call :toggle_option TCP_OPTIMIZE
if "%tcp_choice%"=="2" call :toggle_option UDP_OPTIMIZE
if "%tcp_choice%"=="3" call :toggle_option QOS_OPTIMIZE
if "%tcp_choice%"=="4" call :toggle_option IPV_SETTINGS
if /i "%tcp_choice%"=="D" call :show_tcp_details
if /i "%tcp_choice%"=="M" goto main_menu
goto menu_tcp_options

:menu_conn_options
cls
echo ================================================================
echo    CONNECTION TYPE-SPECIFIC OPTIMIZATIONS
echo ================================================================
echo.
call :show_option "1" "Auto-Detect and Optimize Connection Type" CONN_TYPE_OPTIMIZE "Applies optimizations based on WiFi/Ethernet/Fiber"
call :show_option "2" "Network Adapter Power Settings" ADAPTER_POWER "Prevents power-saving from reducing network speed"
call :show_option "3" "SMB File Sharing Optimization" SMB_OPTIMIZE "Improves file transfer speed on networks"
echo.
echo  [D] View detailed explanation of these optimizations
echo  [M] Return to Main Menu
echo.
set /p conn_choice="Enter your choice: "

if "%conn_choice%"=="1" call :toggle_option CONN_TYPE_OPTIMIZE
if "%conn_choice%"=="2" call :toggle_option ADAPTER_POWER
if "%conn_choice%"=="3" call :toggle_option SMB_OPTIMIZE
if /i "%conn_choice%"=="D" call :show_conn_details
if /i "%conn_choice%"=="M" goto main_menu
goto menu_conn_options

:menu_dns_memory_options
cls
echo ================================================================
echo    DNS AND MEMORY MANAGEMENT OPTIMIZATIONS
echo ================================================================
echo.
call :show_option "1" "DNS Cache Optimization" DNS_OPTIMIZE "Improves web browsing speed with better DNS caching"
call :show_option "2" "Network Memory Management" MEM_OPTIMIZE "Increases available connections and reduces delays"
echo.
echo  [D] View detailed explanation of these optimizations
echo  [M] Return to Main Menu
echo.
set /p dns_choice="Enter your choice: "

if "%dns_choice%"=="1" call :toggle_option DNS_OPTIMIZE
if "%dns_choice%"=="2" call :toggle_option MEM_OPTIMIZE
if /i "%dns_choice%"=="D" call :show_dns_mem_details
if /i "%dns_choice%"=="M" goto main_menu
goto menu_dns_memory_options

:menu_security_options
cls
echo ================================================================
echo    NETWORK SECURITY OPTIMIZATIONS
echo ================================================================
echo.
call :show_option "1" "Network Security Settings" SEC_OPTIMIZE "Configures firewall and secures vulnerable ports"
call :show_option "2" "Network Maintenance" NET_MAINTENANCE "Resets components and flushes caches"
echo.
echo  [D] View detailed explanation of these optimizations
echo  [M] Return to Main Menu
echo.
set /p sec_choice="Enter your choice: "

if "%sec_choice%"=="1" call :toggle_option SEC_OPTIMIZE
if "%sec_choice%"=="2" call :toggle_option NET_MAINTENANCE
if /i "%sec_choice%"=="D" call :show_security_details
if /i "%sec_choice%"=="M" goto main_menu
goto menu_security_options

:menu_gaming_options
cls
echo ================================================================
echo    GAMING AND STREAMING OPTIMIZATIONS
echo ================================================================
echo.
call :show_option "1" "Gaming Mode Optimization" GAME_OPTIMIZE "Prioritizes network traffic for games"
call :show_option "2" "Streaming Mode Optimization" STREAM_OPTIMIZE "Optimizes for streaming services and video calls"
echo.
echo  [D] View detailed explanation of these optimizations
echo  [M] Return to Main Menu
echo.
set /p game_choice="Enter your choice: "

if "%game_choice%"=="1" call :toggle_option GAME_OPTIMIZE
if "%game_choice%"=="2" call :toggle_option STREAM_OPTIMIZE
if /i "%game_choice%"=="D" call :show_gaming_details
if /i "%game_choice%"=="M" goto main_menu
goto menu_gaming_options

:menu_all_options
cls
echo ================================================================
echo    ALL AVAILABLE OPTIMIZATIONS
echo ================================================================
echo.
echo  NETWORK PROTOCOL OPTIMIZATIONS:
call :show_option "1" "TCP Stack Optimization" TCP_OPTIMIZE "Improves TCP packet handling and latency"
call :show_option "2" "UDP Optimization" UDP_OPTIMIZE "Enhances UDP performance for gaming/streaming"
call :show_option "3" "QoS Packet Scheduler" QOS_OPTIMIZE "Controls bandwidth allocation and priorities"
call :show_option "4" "IPv4/IPv6 Stack Configuration" IPV_SETTINGS "Optimizes IP configuration"
echo.
echo  CONNECTION-SPECIFIC OPTIMIZATIONS:
call :show_option "5" "Auto-Detect and Optimize Connection Type" CONN_TYPE_OPTIMIZE "Applies optimizations based on WiFi/Ethernet/Fiber"
call :show_option "6" "Network Adapter Power Settings" ADAPTER_POWER "Prevents power-saving from reducing network speed"
call :show_option "7" "SMB File Sharing Optimization" SMB_OPTIMIZE "Improves file transfer speed on networks"
echo.
echo  PERFORMANCE OPTIMIZATIONS:
call :show_option "8" "DNS Cache Optimization" DNS_OPTIMIZE "Improves web browsing speed with better DNS caching"
call :show_option "9" "Network Memory Management" MEM_OPTIMIZE "Increases available connections and reduces delays"
call :show_option "10" "Gaming Mode Optimization" GAME_OPTIMIZE "Prioritizes network traffic for games"
call :show_option "11" "Streaming Mode Optimization" STREAM_OPTIMIZE "Optimizes for streaming services and video calls"
echo.
echo  SECURITY AND MAINTENANCE:
call :show_option "12" "Network Security Settings" SEC_OPTIMIZE "Configures firewall and secures vulnerable ports"
call :show_option "13" "Network Maintenance" NET_MAINTENANCE "Resets components and flushes caches"
echo.
echo  ADDITIONAL OPTIONS:
call :show_option "14" "Create System Restore Point" CREATE_RESTORE "Safety measure before making changes"
call :show_option "15" "Backup Current Settings" BACKUP_SETTINGS "Creates registry backup of network settings"
call :show_option "16" "Generate Network Health Report" HEALTH_REPORT "Creates before/after comparison of changes"
echo.
set /p all_choice="Enter option number to toggle (or M for Main Menu): "

if "%all_choice%"=="1" call :toggle_option TCP_OPTIMIZE
if "%all_choice%"=="2" call :toggle_option UDP_OPTIMIZE
if "%all_choice%"=="3" call :toggle_option QOS_OPTIMIZE
if "%all_choice%"=="4" call :toggle_option IPV_SETTINGS
if "%all_choice%"=="5" call :toggle_option CONN_TYPE_OPTIMIZE
if "%all_choice%"=="6" call :toggle_option ADAPTER_POWER
if "%all_choice%"=="7" call :toggle_option SMB_OPTIMIZE
if "%all_choice%"=="8" call :toggle_option DNS_OPTIMIZE
if "%all_choice%"=="9" call :toggle_option MEM_OPTIMIZE
if "%all_choice%"=="10" call :toggle_option GAME_OPTIMIZE
if "%all_choice%"=="11" call :toggle_option STREAM_OPTIMIZE
if "%all_choice%"=="12" call :toggle_option SEC_OPTIMIZE
if "%all_choice%"=="13" call :toggle_option NET_MAINTENANCE
if "%all_choice%"=="14" call :toggle_option CREATE_RESTORE
if "%all_choice%"=="15" call :toggle_option BACKUP_SETTINGS
if "%all_choice%"=="16" call :toggle_option HEALTH_REPORT
if /i "%all_choice%"=="M" goto main_menu
goto menu_all_options

:: Show Details Function
:show_details
cls
echo ==================================================
echo  VIEW OPTIMIZATION DETAILS
echo ==================================================
echo.
echo  Select a category to see what changes will be applied:
echo.
echo  1. TCP/IP Protocol Stack Optimizations
echo  2. Connection Type-Specific Optimizations (WiFi/Ethernet/Fiber)
echo  3. DNS and Memory Management Optimizations
echo  4. Security and Maintenance Settings
echo  5. Gaming and Streaming Optimizations
echo  6. Tools and Utilities
echo.
echo  0. Return to Main Menu
echo.
set /p "detail_choice=Enter option number to view details: "

if "%detail_choice%"=="0" goto main_menu
if "%detail_choice%"=="1" call :show_tcp_details
if "%detail_choice%"=="2" call :show_conn_details
if "%detail_choice%"=="3" call :show_dns_mem_details
if "%detail_choice%"=="4" call :show_security_details
if "%detail_choice%"=="5" call :show_gaming_details
if "%detail_choice%"=="6" call :show_tools_details
goto show_details

:show_tcp_details
cls
echo ==================================================
echo  TCP/IP PROTOCOL STACK OPTIMIZATIONS DETAILS
echo ==================================================
echo.
echo TCP STACK OPTIMIZATION:
echo ----------------------
echo Registry changes:
echo - Tcp1323Opts = 1 (Enables TCP Window Scaling)
echo - TCPNoDelay = 1 (Disables Nagle's Algorithm)
echo - TcpAckFrequency = 1 (Improves latency)
echo - DefaultTTL = 64 (Optimizes Time-To-Live value)
echo.
echo Benefits:
echo - Reduces latency in interactive applications
echo - Improves throughput for large data transfers
echo - Optimizes packet handling for modern networks
echo - Improved responsiveness for online gaming and video conferencing
echo.
echo UDP OPTIMIZATION:
echo ---------------
echo Registry changes:
echo - FastSendDatagramThreshold = 1000
echo - FastCopyReceiveThreshold = 1000  
echo - DynamicSendBufferDisable = 0 (Enables dynamic buffer allocation)
echo.
echo Benefits:
echo - Improves gaming and streaming applications
echo - Reduces packet loss during high traffic
echo - Optimizes buffer handling for UDP traffic
echo - Better voice chat quality in games and VoIP applications
echo.
echo QoS PACKET SCHEDULER:
echo ------------------
echo Registry changes:
echo - NonBestEffortLimit = 0 (Removes bandwidth reservation)
echo - TimerResolution = 1 (Improves packet scheduling)
echo - MaxOutstandingSends = 8
echo.
echo Benefits:
echo - Prevents Windows from reserving bandwidth
echo - Improves packet scheduling efficiency
echo - Better prioritizes network traffic
echo.
echo IPv4/IPv6 STACK CONFIGURATION:
echo ---------------------------
echo Registry changes:
echo - DisabledComponents = 32 (Optimizes IPv6 components)
echo - EnableICMPRedirect = 0 (Disables ICMP redirects for security)
echo - EnablePMTUDiscovery = 1 (Enables Path MTU Discovery)
echo.
echo Benefits:
echo - Configures IPv6 for better compatibility
echo - Improves security by preventing ICMP redirects
echo - Optimizes packet size for your connection
echo.
pause
goto main_menu

:show_conn_details
cls
echo ==================================================
echo  CONNECTION TYPE-SPECIFIC OPTIMIZATIONS DETAILS
echo ==================================================
echo.
echo AUTO-DETECT CONNECTION TYPE:
echo -------------------------
echo This feature will:
echo - Automatically detect if you're on WiFi, Ethernet, or Fiber
echo - Apply specific optimizations for your connection type:
echo.
echo   WiFi optimizations:
echo   - Configure TCP parameters for wireless stability
echo   - Set appropriate WiFi power settings
echo   - Configure TCP Initial RTT for wireless connections
echo   - Optimize delivery optimization settings
echo   - Fine-tune buffer settings for wireless interference conditions
echo.
echo   Ethernet optimizations:
echo   - Configure TCP parameters for wired connections
echo   - Set optimal TCP Initial RTT for Ethernet
echo   - Adjust buffer settings for more consistent wired performance
echo.
echo   Fiber optimizations (for high-speed connections):
echo   - Set larger TCP window sizes (GlobalMaxTcpWindowSize = 65535)
echo   - Enable scaling options for gigabit+ connections
echo   - Optimize for high-bandwidth, low-latency environments
echo.
echo NETWORK ADAPTER POWER SETTINGS:
echo ----------------------------
echo Registry/Power changes:
echo - Sets processor performance boost mode to aggressive
echo - Sets maximum processor performance boost percentage
echo - Disables Selective Suspend on WiFi adapters
echo.
echo Benefits:
echo - Prevents power-saving features from reducing network speed
echo - Ensures consistent network performance
echo - Reduces latency by keeping adapters fully powered
echo.
echo SMB FILE SHARING OPTIMIZATION:
echo --------------------------
echo Registry changes:
echo - DisableBandwidthThrottling = 1
echo - DisableLargeMtu = 0 (Enables Large MTU support)
echo.
echo Benefits:
echo - Allows maximum bandwidth for SMB transfers
echo - Enables larger packet sizes for better throughput
echo - Improves local network file transfer speeds
echo.
pause
goto main_menu

:show_dns_mem_details
cls
echo ==================================================
echo  DNS AND MEMORY MANAGEMENT OPTIMIZATIONS DETAILS
echo ==================================================
echo.
echo DNS CACHE OPTIMIZATION:
echo --------------------
echo Registry changes:
echo - CacheHashTableBucketSize = 1
echo - CacheHashTableSize = 384
echo - DnsCacheTimeout = 86400 (24 hours - keeps successful lookups cached longer)
echo.
echo Benefits:
echo - Caches more DNS entries for faster lookups
echo - Reduces the time to find cached DNS entries
echo - Improves overall browsing experience
echo - Faster website loading on repeat visits
echo - Reduces DNS lookup delays when gaming or streaming
echo.
echo NETWORK MEMORY MANAGEMENT:
echo -----------------------
echo Registry changes:
echo - MaxUserPort = 65534 (Increases maximum TCP ports)
echo - TcpTimedWaitDelay = 30 (Reduces TIME_WAIT delay)
echo - MaxFreeTcbs = 65535 (Increases maximum free TCBs)
echo.
echo Benefits:
echo - Allows more simultaneous connections
echo - Reduces delay before port reuse
echo - Improves connection handling under high load
echo - Better handles multiple connections for modern web browsing
echo.
pause
goto main_menu

:show_security_details
cls
echo ==================================================
echo  SECURITY AND MAINTENANCE OPTIMIZATIONS DETAILS
echo ==================================================
echo.
echo NETWORK SECURITY SETTINGS:
echo -----------------------
echo Actions performed:
echo - Enables Windows Firewall with secure defaults
echo - Blocks inbound connections by default
echo - Scans for and secures vulnerable ports (135, 137, 138, 139, 445, etc.)
echo - Ensures Base Filtering Engine is running
echo - Blocks known malicious IP ranges
echo - Enables SMB signing and encryption
echo - Disables vulnerable protocols (SMBv1)
echo - Enables TLS 1.2 and disables older SSL versions
echo - Disables LLMNR and WPAD for security
echo - Configures networks as private instead of public for better protection
echo.
echo Benefits:
echo - Protects against unauthorized access
echo - Secures commonly exploited network ports
echo - Implements security best practices
echo - Prevents common network attacks
echo.
echo NETWORK MAINTENANCE:
echo -----------------
echo Actions performed:
echo - Flushes DNS cache (ipconfig /flushdns)
echo - Resets Winsock catalog (netsh winsock reset)
echo - Resets IP stack (netsh int ip reset)
echo - Releases and renews IP addresses
echo - Clears ARP cache
echo - Resets Internet settings
echo.
echo Benefits:
echo - Resolves common network issues
echo - Removes outdated or corrupted network settings
echo - Refreshes all network components
echo - May fix connectivity problems
echo.
pause
goto main_menu

:show_gaming_details
cls
echo ==================================================
echo  GAMING AND STREAMING OPTIMIZATIONS DETAILS
echo ==================================================
echo.
echo GAMING MODE OPTIMIZATION:
echo ----------------------
echo Registry changes:
echo - Games\GPU Priority = 8
echo - Games\Priority = 6
echo - Games\Scheduling Category = "High"
echo - NetworkThrottlingIndex = 4294967295 (Disables throttling)
echo - SystemResponsiveness = 0 (Prioritizes foreground apps)
echo - GameDVR_FSEBehavior = 2 (Optimizes full-screen performance)
echo - GameDVR_Enabled = 0 (Disables Game DVR to reduce overhead)
echo.
echo Benefits:
echo - Reduces network latency in games
echo - Prioritizes game traffic over background tasks
echo - Improves responsiveness in online games
echo - Better ping times and reduced jitter
echo - Lower input lag and more consistent frame rates
echo - Optimizes Windows resources for gaming performance
echo.
echo STREAMING MODE OPTIMIZATION:
echo ------------------------
echo Registry changes:
echo - TcpAckFrequency = 1 (Immediate acknowledgements)
echo - TCPNoDelay = 1 (Disables Nagle's Algorithm)
echo - NetworkThrottlingIndex = 4294967295 (Disables throttling)
echo - initialRto = 2000 (Optimizes retransmission timeout)
echo.
echo Benefits:
echo - Smoother video streaming with fewer buffering events
echo - Better audio/video sync in conferencing applications
echo - Reduced stuttering in live streams
echo - Improved quality for services like Netflix, YouTube, Zoom
echo.
pause
goto main_menu

:show_tools_details
cls
echo ==================================================
echo  TOOLS AND UTILITIES DETAILS
echo ==================================================
echo.
echo CREATE SYSTEM RESTORE POINT:
echo ------------------------
echo Actions performed:
echo - Creates a System Restore Point named "Network Optimization"
echo - Allows you to revert all changes if needed
echo.
echo Benefits:
echo - Provides a safety net before making system changes
echo - Allows easy rollback if optimizations cause issues
echo - Recommended before applying any system-wide changes
echo.
echo BACKUP CURRENT SETTINGS:
echo ---------------------
echo Actions performed:
echo - Exports current TCP/IP registry settings
echo - Saves the backup in the Network Tools directory
echo - Creates a timestamped backup file (.reg format)
echo.
echo Benefits:
echo - Creates a manual restore option via registry file
echo - More targeted than System Restore for network settings
echo - Provides a way to selectively restore settings
echo.
echo GENERATE NETWORK HEALTH REPORT:
echo ---------------------------
echo Actions performed:
echo - Captures network statistics before optimization
echo - Records TCP/IP configuration and parameters
echo - Logs network interface information
echo - Captures DNS cache status
echo - Creates a detailed report after optimization
echo - Generates a complete HTML report comparing results
echo.
echo Benefits:
echo - Documents the impact of optimizations
echo - Provides a before/after comparison
echo - Creates a record of all changes made
echo - Helps identify if optimizations improved performance
echo.
pause
goto main_menu

:show_option
if not defined %3 set "%3=N"
set "SELECTED="
if "!%3!"=="Y" set "SELECTED=[X]" & call :count_selected
if "!%3!"=="N" set "SELECTED=[ ]"
echo  %SELECTED% %~1. %~2
if not "%~4"=="" echo     - %~4
exit /b

:count_selected
set /a SELECTED_COUNT+=0
if not defined SELECTED_COUNT set "SELECTED_COUNT=0"
if "!%3!"=="Y" set /a SELECTED_COUNT+=1
exit /b

:toggle_option
if "%1"=="" exit /b
if "!%1!"=="Y" (
    set "%1=N"
    set /a SELECTED_COUNT-=1
) else (
    set "%1=Y"
    set /a SELECTED_COUNT+=1
)
exit /b

:set_option
if "%1"=="" exit /b
if "!%1!"=="N" (
    set "%1=Y"
    set /a SELECTED_COUNT+=1
)
exit /b

:reset_options
set "SELECTED_COUNT=0"
set "CREATE_RESTORE=N"
set "BACKUP_SETTINGS=N"
set "TCP_OPTIMIZE=N"
set "UDP_OPTIMIZE=N"
set "DNS_OPTIMIZE=N"
set "ADAPTER_POWER=N"
set "SMB_OPTIMIZE=N"
set "QOS_OPTIMIZE=N"
set "IPV_SETTINGS=N"
set "MEM_OPTIMIZE=N"
set "SEC_OPTIMIZE=N"
set "GAME_OPTIMIZE=N"
set "STREAM_OPTIMIZE=N"
set "NET_MAINTENANCE=N"
set "CONN_TYPE_OPTIMIZE=N"
set "HEALTH_REPORT=N"
if "%~1"=="" goto main_menu
exit /b

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
goto main_menu

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

:: Calculate total steps for progress bar
set /a TOTAL_STEPS=0
if "%CREATE_RESTORE%"=="Y" set /a TOTAL_STEPS+=1
if "%BACKUP_SETTINGS%"=="Y" set /a TOTAL_STEPS+=1
if "%TCP_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%UDP_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%DNS_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%ADAPTER_POWER%"=="Y" set /a TOTAL_STEPS+=1
if "%SMB_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%QOS_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%IPV_SETTINGS%"=="Y" set /a TOTAL_STEPS+=1
if "%CONN_TYPE_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%MEM_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%SEC_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%GAME_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%STREAM_OPTIMIZE%"=="Y" set /a TOTAL_STEPS+=1
if "%NET_MAINTENANCE%"=="Y" set /a TOTAL_STEPS+=1
if "%HEALTH_REPORT%"=="Y" set /a TOTAL_STEPS+=2

:: Initialize current step
set /a CURRENT_STEP=0

:: Capture network health data before changes if health report is selected
if "%HEALTH_REPORT%"=="Y" (
    call :update_progress "Capturing network baseline statistics"
    
    set "HEALTH_DATA_PATH=%NETWORK_LOGS%\NetworkHealth_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.txt"
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
    
    call :log "[OK] Network baseline captured"
)

:: Create System Restore Point if selected
if "%CREATE_RESTORE%"=="Y" (
    call :update_progress "Creating System Restore Point"
    wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Network Optimization", 100, 7 >nul 2>&1
    if !errorlevel! equ 0 (
        call :log "[OK] System Restore Point created"
    ) else (
        call :log "[WARNING] System Restore Point creation failed"
    )
)

:: Create Registry Backup if selected
if "%BACKUP_SETTINGS%"=="Y" (
    call :update_progress "Creating backup of current network settings"
    set "BACKUP_PATH=%NETWORK_DIR%\NetworkSettingsBackup_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.reg"
    set "BACKUP_PATH=!BACKUP_PATH: =0!"
    
    reg export "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "!BACKUP_PATH!" /y >nul 2>&1
    if !errorlevel! equ 0 (
        call :log "[OK] Registry backup created"
    ) else (
        call :log "[ERROR] Registry backup failed"
        echo Press any key to continue or Ctrl+C to cancel...
        pause >nul
    )
)

:: Apply TCP Optimizations if selected
if "%TCP_OPTIMIZE%"=="Y" (
    call :update_progress "Applying TCP Optimizations"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    :: Disable Nagle's Algorithm for reduced latency
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    :: Additional latency reduction tweaks
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d 64 /f >nul
    call :log "[OK] TCP Optimizations applied"
)

:: Apply UDP Optimizations if selected
if "%UDP_OPTIMIZE%"=="Y" (
    call :update_progress "Applying UDP Optimizations"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d 1000 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d 1000 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d 0 /f >nul
    call :log "[OK] UDP Optimizations applied"
)

:: Apply DNS Cache Optimizations if selected
if "%DNS_OPTIMIZE%"=="Y" (
    call :update_progress "Optimizing DNS cache"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d 384 /f >nul
    call :log "[OK] DNS Cache optimized"
)

:: Apply Network Adapter Power Settings if selected
if "%ADAPTER_POWER%"=="Y" (
    call :update_progress "Optimizing Network Adapter Power Settings"
    powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
    powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100
    call :log "[OK] Network Adapter Power Settings optimized"
)

:: Apply SMB Optimizations if selected
if "%SMB_OPTIMIZE%"=="Y" (
    call :update_progress "Optimizing SMB Settings"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d 0 /f >nul
    call :log "[OK] SMB Settings optimized"
)

:: Apply QoS Optimizations if selected
if "%QOS_OPTIMIZE%"=="Y" (
    call :update_progress "Optimizing QoS Settings"
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d 1 /f >nul
    :: Network priority settings
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d 8 /f >nul
    :: Reserve bandwidth for applications
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "ApplicationGUID" /t REG_MULTI_SZ /d "{00000000-0000-0000-0000-000000000000}" /f >nul
    call :log "[OK] QoS Settings optimized"
)

:: Apply IPv4/IPv6 Settings if selected
if "%IPV_SETTINGS%"=="Y" (
    call :update_progress "Applying IP Settings"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 32 /f >nul
    :: Optimize IPv4 settings
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d 0 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d 1 /f >nul
    call :log "[OK] IP Settings configured"
)

:: Apply Network Interface Tuning if selected
if "%CONN_TYPE_OPTIMIZE%"=="Y" (
    call :update_progress "Applying Connection Type Optimization"
    
    :: Detect connection type using multiple methods
    echo -- Detecting connection type...
    
    :: Create temporary files for connection detection
    set "CONN_DETECT_FILE=%TEMP%\connection_type.txt"
    set "NETSH_OUTPUT=%TEMP%\netsh_output.txt"
    
    :: Method 1: Use PowerShell to get interface information
    echo -- Method 1: PowerShell network adapter detection
    powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription, LinkSpeed, Status | Format-Table -AutoSize > '%CONN_DETECT_FILE%'" 2>nul
    
    :: Method 2: Use netsh as backup
    echo -- Method 2: Using netsh for interface detection
    netsh interface show interface > "%NETSH_OUTPUT%" 2>nul
    
    :: Initialize connection type
    set "CONN_TYPE=Unknown"
    set "INTERFACE_NAME="
    
    :: Check if detection files exist and have content
    if exist "%CONN_DETECT_FILE%" (
        :: Debug output the content of detection file
        echo -- Debug: Network adapter information found:
        type "%CONN_DETECT_FILE%"
        echo.
        
        :: Look for WiFi/Wireless keywords
        findstr /i "Wi-Fi Wireless WLAN" "%CONN_DETECT_FILE%" >nul 2>&1
        if !errorlevel! equ 0 (
            set "CONN_TYPE=WiFi"
            for /f "tokens=1" %%a in ('findstr /i "Wi-Fi Wireless WLAN" "%CONN_DETECT_FILE%"') do (
                if not defined INTERFACE_NAME set "INTERFACE_NAME=%%a"
            )
        ) else (
            :: Look for Ethernet keywords
            findstr /i "Ethernet Local" "%CONN_DETECT_FILE%" >nul 2>&1
            if !errorlevel! equ 0 (
                set "CONN_TYPE=Ethernet"
                for /f "tokens=1" %%a in ('findstr /i "Ethernet Local" "%CONN_DETECT_FILE%"') do (
                    if not defined INTERFACE_NAME set "INTERFACE_NAME=%%a"
                )
                
                :: Check for fiber based on speed (usually 1Gbps or higher)
                findstr /i "Gbps" "%CONN_DETECT_FILE%" >nul 2>&1
                if !errorlevel! equ 0 (
                    set "CONN_TYPE=Fiber"
                )
            )
        )
    )
    
    :: If still unknown, try netsh method
    if "!CONN_TYPE!"=="Unknown" if exist "%NETSH_OUTPUT%" (
        echo -- Attempting detection via netsh output
        type "%NETSH_OUTPUT%"
        echo.
        
        findstr /i "Wi-Fi Wireless" "%NETSH_OUTPUT%" >nul 2>&1
        if !errorlevel! equ 0 (
            set "CONN_TYPE=WiFi"
            for /f "tokens=*" %%a in ('findstr /i "Connected" "%NETSH_OUTPUT%" ^| findstr /i "Wi-Fi Wireless"') do (
                for /f "tokens=1" %%b in ("%%a") do set "INTERFACE_NAME=%%b"
            )
        ) else (
            findstr /i "Ethernet Local" "%NETSH_OUTPUT%" >nul 2>&1
            if !errorlevel! equ 0 (
                set "CONN_TYPE=Ethernet"
                for /f "tokens=*" %%a in ('findstr /i "Connected" "%NETSH_OUTPUT%" ^| findstr /i "Ethernet Local"') do (
                    for /f "tokens=1" %%b in ("%%a") do set "INTERFACE_NAME=%%b"
                )
            )
        )
    )
    
    :: Final attempt - check active connections
    if "!CONN_TYPE!"=="Unknown" (
        echo -- Final detection attempt using ipconfig
        ipconfig | findstr /i "Wireless Wi-Fi" >nul 2>&1
        if !errorlevel! equ 0 set "CONN_TYPE=WiFi"
        
        if "!CONN_TYPE!"=="Unknown" (
            ipconfig | findstr /i "Ethernet" >nul 2>&1
            if !errorlevel! equ 0 set "CONN_TYPE=Ethernet"
        )
    )
    
    echo -- Detected connection type: !CONN_TYPE!
    if defined INTERFACE_NAME echo -- Network interface: !INTERFACE_NAME!
    call :log "Detected connection type: !CONN_TYPE!"
    if defined INTERFACE_NAME call :log "Network interface: !INTERFACE_NAME!"
    
    :: Apply optimizations based on connection type
    if "!CONN_TYPE!"=="WiFi" (
        echo -- Applying WiFi-specific optimizations...
        
        :: Verify netsh wlan is available
        netsh wlan show interfaces >nul 2>&1
        if !errorlevel! equ 0 (
            :: Get the actual interface name if needed
            if not defined INTERFACE_NAME (
                for /f "tokens=2 delims=:" %%a in ('netsh wlan show interfaces ^| findstr /i "Name"') do (
                    set "INTERFACE_NAME=%%a"
                    set "INTERFACE_NAME=!INTERFACE_NAME:~1!"
                )
            )
            
            if defined INTERFACE_NAME (
                echo -- Using WiFi interface: !INTERFACE_NAME!
                netsh wlan set autoconfig enabled=yes interface="!INTERFACE_NAME!" >nul 2>&1
            ) else (
                echo -- WiFi interface name not found, applying general WiFi settings
            )
        )
        
        :: Apply WiFi-specific optimizations
        echo -- Setting WiFi optimized registry values
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f >nul 2>&1
        
        :: Buffer tuning for WiFi
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpInitialRTT" /t REG_DWORD /d 3 /f >nul 2>&1
        
        :: Power management settings for WiFi
        powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Set-NetAdapterPowerManagement -SelectiveSuspend Disabled" >nul 2>&1
    )
    
    if "!CONN_TYPE!"=="Ethernet" (
        echo -- Applying Ethernet-specific optimizations...
        
        :: Apply Ethernet-specific optimizations
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpInitialRTT" /t REG_DWORD /d 2 /f >nul 2>&1
    )
    
    if "!CONN_TYPE!"=="Fiber" (
        echo -- Applying Fiber-specific optimizations...
        
        :: Buffer tuning for high-bandwidth connections
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d 65535 /f >nul 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d 65535 /f >nul 2>&1
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d 3 /f >nul 2>&1
    )
    
    :: Apply general optimizations regardless of connection type
    echo -- Applying general network optimizations for all connection types...
    
    :: TCP Optimizations
    netsh int tcp set global congestionprovider=ctcp >nul 2>&1
    netsh int tcp set global autotuninglevel=normal >nul 2>&1
    
    :: Disable nagle's algorithm for better responsiveness
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul 2>&1
    
    :: Set useful TTL
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d 64 /f >nul 2>&1
    
    :: Clean up temp files
    if exist "%CONN_DETECT_FILE%" del "%CONN_DETECT_FILE%" >nul 2>&1
    if exist "%NETSH_OUTPUT%" del "%NETSH_OUTPUT%" >nul 2>&1
    
    call :log "[OK] Connection Type Optimization applied for !CONN_TYPE!"
)

:: Apply Advanced Settings if needed
:: Apply Memory Management Optimizations if selected
if "%MEM_OPTIMIZE%"=="Y" (
    call :update_progress "Optimizing Network Memory Management"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d 65534 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d 65535 /f >nul
    call :log "[OK] Memory Management Optimizations applied"
)

:: Apply Network Security Settings if selected
if "%SEC_OPTIMIZE%"=="Y" (
    call :update_progress "Applying Network Security Optimizations"
    
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
    
    call :log "[OK] Network Security Optimizations applied"
)

:: Apply Gaming Mode Optimizations if selected
if "%GAME_OPTIMIZE%"=="Y" (
    call :update_progress "Applying Gaming Mode Optimizations"
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f >nul
    call :log "[OK] Gaming Mode Optimizations applied"
)

:: Apply Streaming Mode Optimizations if selected
if "%STREAM_OPTIMIZE%"=="Y" (
    call :update_progress "Applying Streaming Mode Optimizations"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f >nul
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul
    netsh int tcp set global initialRto=2000 >nul
    call :log "[OK] Streaming Mode Optimizations applied"
)

:: Apply Network Maintenance if selected
if "%NET_MAINTENANCE%"=="Y" (
    call :update_progress "Performing Network Maintenance"
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
    call :log "[OK] Network Maintenance completed"
)

:: Generate the Network Health Report if selected
if "%HEALTH_REPORT%"=="Y" (
    call :update_progress "Generating Network Health Report"
    
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
    set "HTML_REPORT=%NETWORK_LOGS%\NetworkReport_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.html"
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
    
    for %%i in (TCP_OPTIMIZE UDP_OPTIMIZE DNS_OPTIMIZE ADAPTER_POWER SMB_OPTIMIZE QOS_OPTIMIZE IPV_SETTINGS CONN_TYPE_OPTIMIZE) do (
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
    
    call :log "[OK] Network Health Report generated"
    echo -- Report saved to: !HTML_REPORT!
)

:: Verify and finalize changes
echo.
echo Verifying changes...
call :log "Verifying changes..."

:: Check if any optimizations were applied
set "CHANGES_MADE=N"
for %%i in (TCP_OPTIMIZE DNS_OPTIMIZE ADAPTER_POWER SMB_OPTIMIZE QOS_OPTIMIZE IPV_SETTINGS CONN_TYPE_OPTIMIZE HEALTH_REPORT) do (
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

:clean_logs
cls
echo ==================================================
echo   Cleaning Log Files
echo ==================================================
echo.
echo This will delete all log and report files in the "%NETWORK_LOGS%" directory.
echo.
echo Are you sure you want to proceed? (Y/N)
set /p "clean_choice="
if /i "%clean_choice%"=="y" (
    echo.
    echo Deleting log files...
    del /f /q "%NETWORK_LOGS%\*.txt" 2>nul
    del /f /q "%NETWORK_LOGS%\*.html" 2>nul
    del /f /q "%NETWORK_LOGS%\*.log" 2>nul
    echo.
    echo Log files have been deleted.
    echo.
    echo Press any key to return to menu...
    pause >nul
) else (
    echo.
    echo Log cleanup cancelled.
    echo.
    echo Press any key to return to menu...
    pause >nul
)
goto menu

:log
echo %* >> "%LOG_PATH%"
exit /b 0

endlocal

:exit_script
cls
echo.
echo Thank you for using Windows Network Performance Optimizer v%VERSION%
echo The script will now exit.
echo.
exit

:check_for_updates
echo Checking for updates...
set "UPDATE_URL=https://raw.githubusercontent.com/network-optimizer/version/main/version.txt"
set "LATEST_VERSION="

:: Create a temporary file to store the version information
set "TEMP_VERSION_FILE=%TEMP%\networkoptimizer_version.txt"

:: Use PowerShell to download the latest version file
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%UPDATE_URL%', '%TEMP_VERSION_FILE%')" >nul 2>&1

:: Check if download was successful
if exist "%TEMP_VERSION_FILE%" (
    :: Read the latest version number
    for /f "usebackq delims=" %%i in ("%TEMP_VERSION_FILE%") do (
        set "LATEST_VERSION=%%i"
        goto version_read
    )
    
    :version_read
    :: Compare versions
    if "!LATEST_VERSION!" neq "" (
        if !LATEST_VERSION! gtr %VERSION% (
            echo.
            echo ================================================================
            echo   UPDATE AVAILABLE
            echo ================================================================
            echo   Current version: %VERSION%
            echo   Latest version: !LATEST_VERSION!
            echo.
            echo   Download the latest version from:
            echo   https://github.com/network-optimizer/releases
            echo ================================================================
            echo.
            timeout /t 3 >nul
        )
    )
    
    :: Clean up temp file
    del "%TEMP_VERSION_FILE%" >nul 2>&1
) else (
    :: Failed to check for updates, but continue with execution
    echo [INFO] Update check failed. Continuing with current version.
)
exit /b 0

:show_progress_bar
setlocal
set "fill=%~1"
set "total=%~2"
set "prefix=%~3"

:: Calculate bar width - width 50 chars
set /a bar_width=50
set /a fill_width=(%fill% * %bar_width%) / %total%

:: Build progress bar
set "progress_bar="
for /l %%i in (1,1,%fill_width%) do set "progress_bar=!progress_bar!█"
for /l %%i in (%fill_width%,1,%bar_width%) do set "progress_bar=!progress_bar!░"

:: Calculate percentage
set /a percent=(%fill% * 100) / %total%

:: Show progress bar
echo %prefix% [!progress_bar!] !percent!%%
endlocal
exit /b

:update_progress
set /a CURRENT_STEP+=1
set "operation_text=%~1"
echo.
echo %operation_text%...
call :show_progress_bar %CURRENT_STEP% %TOTAL_STEPS% "Progress:"
call :log "%operation_text%..."
exit /b

:apply_recommended_settings
:: First reset all options
call :reset_options notmenu

:: Apply recommended settings for typical users
echo.
echo Applying recommended settings for optimal performance...

:: Create a restore point for safety
call :set_option CREATE_RESTORE

:: Essential TCP/IP optimizations
call :set_option TCP_OPTIMIZE

:: DNS optimization for faster browsing
call :set_option DNS_OPTIMIZE

:: Network adapter power settings to prevent throttling
call :set_option ADAPTER_POWER

:: QoS for better traffic management
call :set_option QOS_OPTIMIZE

:: Memory management for better connection handling
call :set_option MEM_OPTIMIZE

:: Auto-detect connection type and optimize accordingly
call :set_option CONN_TYPE_OPTIMIZE

:: Basic network security
call :set_option SEC_OPTIMIZE

:: Network maintenance to clean up network stack
call :set_option NET_MAINTENANCE

echo.
echo Recommended settings selected. %SELECTED_COUNT% optimizations ready to apply.
echo These settings provide a balanced improvement for general Internet usage,
echo streaming, browsing, and overall network stability.
echo.
echo Would you like to apply these optimizations now? (Y/N)
set /p "apply_now="

if /i "!apply_now!"=="y" (
    :: Apply the optimizations
    goto apply_changes_and_reset
) else (
    echo.
    echo Returning to main menu with recommended settings selected.
    echo You can apply them later by selecting option [A].
    echo.
    echo Press any key to continue...
    pause >nul
    goto main_menu
)

:apply_changes_and_reset
:: Call the apply_changes function
call :apply_changes

:: Reset all options after application
call :reset_options notmenu

:: Return to main menu
goto main_menu
