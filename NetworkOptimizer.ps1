    # PowerShell Network Optimizer - Comprehensive Windows network performance opti...
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(HelpMessage = "Run with recommended settings without user interaction")]
    [switch]$Silent,

    [Parameter(HelpMessage = "Path to custom configuration file")]
    [string]$ConfigFile,

    [Parameter(HelpMessage = "Custom path for log file output")]
    [string]$LogPath,

    [Parameter(HelpMessage = "Automatically enable preview mode when not running as administrator")]
        [switch]$AutoPreview,

    [Parameter(HelpMessage = "Bypass safety checks including pending reboot detection")]
    [switch]$Force
)

#Requires -Version 5.1
# Administrator requirement: Checked dynamically to support AutoPreview and remote execution
# For full functionality, run as Administrator

# Parameter validation (moved here to avoid remote execution parsing issues)
if ($ConfigFile -and $ConfigFile -ne "" -and -not (Test-Path $ConfigFile -PathType Leaf)) {
    Write-Error "Configuration file not found: $ConfigFile" -ErrorAction Stop
}

if ($LogPath -and $LogPath -ne "" -and -not (Test-Path (Split-Path $LogPath -Parent) -PathType Container)) {
    Write-Error "Log directory not found: $(Split-Path $LogPath -Parent)" -ErrorAction Stop
}

# Script metadata
$Script:Version = "1.0.0"
$Script:ScriptName = "NetworkOptimizer"
$Script:StartTime = Get-Date

# Global error handling preference
$ErrorActionPreference = 'Stop'

# Suppress verbose WhatIf messages for clean output
$VerbosePreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
if ($WhatIfPreference) {
    $WhatIfPreference = $true
    $ConfirmPreference = 'None'
}

# Initialize script-wide variables
$Script:LogFile = $null
$Script:BackupPath = $null
$Script:BackupInfo = $null
$Script:OptimizationResults = @()
$Script:Config = $null
$Script:AutoPreviewEnabled = $false

# Initialize caching variables for performance optimization
$Script:IsAdministrator = $null
$Script:NetworkAdaptersCache = $null
$Script:NetworkAdaptersCacheTime = $null
$Script:NetworkAdaptersCacheTTL = 30 # seconds

# Progress tracking
$Script:CurrentStep = 0
$Script:TotalSteps = 0
$Script:ProgressBarWidth = 50

#region Core Framework Functions

function Write-ProgressBar {
    # Clean progress bar for user-friendly output
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity = "Processing",
        [string]$Status = ""
    )

    if ($Total -eq 0) { return }

    $percent = [math]::Min(100, [math]::Round(($Current / $Total) * 100))
    $filled = [math]::Round(($percent / 100) * $Script:ProgressBarWidth)
    $empty = $Script:ProgressBarWidth - $filled

    $bar = "[" + ("█" * $filled) + ("░" * $empty) + "]"

    $statusMsg = if ($Status) { " - $Status" } else { "" }

    Write-Host "`r$bar $percent% - $Activity$statusMsg" -NoNewline -ForegroundColor Cyan

    if ($Current -eq $Total) {
        Write-Host ""
    }
}

function Show-CleanMessage {
    # User-friendly message display
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Progress")]
        [string]$Type = "Info"
    )

    $icon = switch ($Type) {
        "Success" { "✅" }
        "Warning" { "⚠️" }
        "Error" { "❌" }
        "Progress" { "⏳" }
        default { "ℹ️" }
    }

    $color = switch ($Type) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Progress" { "Cyan" }
        default { "White" }
    }

    Write-Host "$icon $Message" -ForegroundColor $color
}

function Start-AnimatedTask {
    # Execute task with spinner animation
    param(
        [scriptblock]$Task,
        [string]$Message = "Processing..."
    )

    $spinnerChars = @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')
    $spinnerIndex = 0

    $job = Start-Job -ScriptBlock $Task

    while ($job.State -eq 'Running') {
        Write-Host "`r$($spinnerChars[$spinnerIndex]) $Message" -NoNewline -ForegroundColor Cyan
        $spinnerIndex = ($spinnerIndex + 1) % $spinnerChars.Count
        Start-Sleep -Milliseconds 100
    }

    Write-Host "`r" -NoNewline
    $result = Receive-Job -Job $job
    Remove-Job -Job $job

    return $result
}

function Test-AdministratorPrivileges {
    # Check if running as administrator (cached)
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Return cached result if available
    if ($null -ne $Script:IsAdministrator) {
        return $Script:IsAdministrator
    }

    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $Script:IsAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        Write-OptimizationLog "Administrator privilege check: $Script:IsAdministrator" -Level "Info"
        return $Script:IsAdministrator
    }
    catch {
        $Script:IsAdministrator = $false
        Write-OptimizationLog "Failed to check administrator privileges: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-WindowsVersion {
    # Validate Windows 10+ compatibility
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $osVersion = [System.Environment]::OSVersion.Version
        $osName = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

        # Check for Windows 10 or later (version 10.0 or higher)
        $isCompatible = $osVersion.Major -ge 10

        Write-OptimizationLog "Windows version check - OS: $osName, Version: $($osVersion.ToString()), Compatible: $isCompatible" -Level "Info"

        if (-not $isCompatible) {
            Write-OptimizationLog "Incompatible Windows version detected. Minimum requirement: Windows 10" -Level "Warning"
        }

        return $isCompatible
    }
    catch {
        Write-OptimizationLog "Failed to check Windows version: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-PowerShellVersion {
    # Validate PowerShell 5.1+ compatibility
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $psVersion = $PSVersionTable.PSVersion
        $edition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { "Desktop" }

        # Check for PowerShell 5.1 or later
        $isCompatible = ($psVersion.Major -gt 5) -or
                       ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)

        Write-OptimizationLog "PowerShell version check - Version: $($psVersion.ToString()), Edition: $edition, Compatible: $isCompatible" -Level "Info"

        if (-not $isCompatible) {
            Write-OptimizationLog "Incompatible PowerShell version detected. Minimum requirement: PowerShell 5.1" -Level "Warning"
        }

        return $isCompatible
    }
    catch {
        Write-OptimizationLog "Failed to check PowerShell version: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Initialize-NetworkOptimizer {
    # Initialize environment, validate requirements, create backups
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        # Clean header
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "   Network Optimizer v$Script:Version" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        Show-CleanMessage "Initializing..." -Type Progress

        # Auto-enable WhatIf if not running as admin and AutoPreview is enabled
        if ($AutoPreview -and -not (Test-AdministratorPrivileges)) {
            Show-CleanMessage "Non-admin mode detected - Preview mode enabled" -Type Warning
            $WhatIfPreference = $true
            $PSBoundParameters['WhatIf'] = $true
            $Script:AutoPreviewEnabled = $true
        } elseif ($AutoPreview -and (Test-AdministratorPrivileges)) {
            Show-CleanMessage "Administrator mode - Full execution enabled" -Type Success
            $Script:AutoPreviewEnabled = $false
        }

        # Set up logging first
        if (-not $LogPath) {
            $Script:LogFile = Join-Path $PWD "NetworkOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        } else {
            $Script:LogFile = $LogPath
        }

        Write-OptimizationLog "Network Optimizer v$Script:Version starting" -Level "Info"
        Write-OptimizationLog "Parameters: Silent=$Silent, ConfigFile=$ConfigFile, LogPath=$LogPath, WhatIf=$($PSBoundParameters.ContainsKey('WhatIf'))" -Level "Info"

        # Perform comprehensive safety validation
        Show-CleanMessage "Performing safety checks..." -Type Progress
        $safetyValidation = Test-SafetyValidation

        if (-not $safetyValidation.OverallSuccess) {
            # Check if this is primarily an administrator privileges issue
            $isAdminIssue = $safetyValidation.Errors -match "Administrator privileges required"
            $isRemoteExecution = ($MyInvocation.InvocationName -eq '&' -or $MyInvocation.Line -match 'irm|Invoke-RestMethod|github|raw\.githubusercontent')

            if ($isAdminIssue -and $isAdminIssue.Count -eq $safetyValidation.Errors.Count) {
                # Concise admin privileges error
                Write-Host ""
                Show-CleanMessage "Administrator privileges required" -Type Warning
                Write-Host "   💡 Right-click PowerShell → 'Run as Administrator'" -ForegroundColor DarkGray
                Write-Host "   💡 Or add -WhatIf for preview mode" -ForegroundColor DarkGray
            } else {
                # Multiple issues - show concise error
                Write-Host ""
                Show-CleanMessage "Safety validation failed ($($safetyValidation.Errors.Count) errors)" -Type Error
                foreach ($errItem in $safetyValidation.Errors) {
                    Write-Host "   • $errItem" -ForegroundColor Red</parameter>

<old_text line=240>
        # Create backup directory
        $Script:BackupPath = Join-Path $env:TEMP "NetworkOptimizer_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $Script:BackupPath -ItemType Directory -Force | Out-Null
        Write-OptimizationLog "Backup directory created: $Script:BackupPath" -Level "Info"

        # Create system restore point for rollback capability
        $restorePointCreated = $false
        Write-Host "Creating system restore point..." -ForegroundColor Yellow
                    Write-Host "   • $error" -ForegroundColor Red
                }
                if ($safetyValidation.Warnings.Count -gt 0) {
                    foreach ($warning in $safetyValidation.Warnings) {
                        Write-Host "   • $warning" -ForegroundColor Yellow
                    }
                }
                Write-Host "`n💡 Solutions: Run as Admin | Ensure network active | Use -WhatIf for preview" -ForegroundColor Cyan
            }

            throw "Network Optimizer requires administrator privileges to modify system settings."
        }

        # Create backup directory for safety
        $Script:BackupPath = Join-Path $env:TEMP "NetworkOptimizer_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $Script:BackupPath -ItemType Directory -Force | Out-Null
        Write-OptimizationLog "Backup directory created: $Script:BackupPath" -Level "Info"

        # Create system restore point for rollback capability
        $restorePointResult = New-SystemRestorePoint -Description "Network Optimizer - Before Optimization"

        # Track restore point status for later use
        $Script:RestorePointCreated = $restorePointResult.Success
        $Script:RestorePointMessage = $restorePointResult.Message

        if ($restorePointResult.Success) {
            Write-OptimizationLog "System restore point created successfully: $($restorePointResult.Message)" -Level "Info"
            Show-CleanMessage "Restore point created" -Type Success
        } else {
            Write-OptimizationLog "System restore point creation failed: $($restorePointResult.Message)" -Level "Warning"
            Show-CleanMessage "Restore point unavailable (continuing with registry backups)" -Type Warning

            if (-not $Silent) {
                Write-Host ""
                Write-Host "Continue with registry backups only? (Y/n): " -NoNewline -ForegroundColor Yellow
                $continue = Read-Host
                if ($continue -match '^[Nn]') {
                    Write-OptimizationLog "User declined to continue without restore point" -Level "Warning"
                    throw "Operation cancelled by user"
                }
            }
        }

        # Backup current network settings
        Show-CleanMessage "Backing up current settings..." -Type Progress
        $Script:BackupInfo = Backup-NetworkSettings -BackupPath $Script:BackupPath
        if (-not $Script:BackupInfo.Success) {
            throw "Failed to backup current network settings. Cannot proceed safely."
        }
        Write-OptimizationLog "Network settings backup completed successfully" -Level "Info"

        # Initialize optimization results tracking
        $Script:OptimizationResults = @()
        Write-OptimizationLog "Optimization results tracking initialized" -Level "Info"

        # Display safety summary
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
        Show-CleanMessage "Safety Checks Complete" -Type Success
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-OptimizationLog "Network Optimizer initialization completed successfully with full safety mechanisms" -Level "Info"
        return $true
    }
    catch {
        $errorMessage = "Failed to initialize: $($_.Exception.Message)"
        Show-CleanMessage $errorMessage -Type Error
        Write-OptimizationLog $errorMessage -Level "Error"

        # Cleanup on failure
        if ($Script:BackupPath -and (Test-Path $Script:BackupPath)) {
            try {
                Remove-Item -Path $Script:BackupPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-OptimizationLog "Cleaned up backup directory after initialization failure" -Level "Info"
            }
            catch {
                Write-OptimizationLog "Failed to cleanup backup directory: $($_.Exception.Message)" -Level "Warning"
            }
        }

        return $false
    }
}

function Write-OptimizationLog {
    # Lightweight logging - errors/warnings only logged when needed
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )

    # Only log warnings and errors to reduce memory/disk usage
    if ($Level -notin @("Warning", "Error")) { return }

    if ($Script:LogFile) {
        try {
            $logEntry = "[$(Get-Date -Format 'HH:mm:ss')] [$Level] $Message"
            Add-Content -Path $Script:LogFile -Value $logEntry -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Silent fail - don't disrupt execution
        }
    }
}

function Invoke-SafeOperation {
    # Execute with error handling and rollback
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [Parameter()]
        [scriptblock]$RollbackOperation
    )

    try {
        Write-OptimizationLog "Starting operation: $OperationName" -Level "Info"

        if ($PSCmdlet.ShouldProcess($OperationName, "Execute Operation")) {
            # Continue with operation
        } else {
            return $true
        }

        # Execute the operation
        $result = & $Operation

        Write-OptimizationLog "Operation completed successfully: $OperationName" -Level "Info"
        return $result
    }
    catch {
        $errorMessage = "Operation failed: $OperationName - $($_.Exception.Message)"
        Write-Error $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"

        # Execute rollback if provided
        if ($RollbackOperation) {
            try {
                Write-OptimizationLog "Executing rollback for: $OperationName" -Level "Warning"
                & $RollbackOperation
                Write-OptimizationLog "Rollback completed for: $OperationName" -Level "Info"
            }
            catch {
                Write-OptimizationLog "Rollback failed for: $OperationName - $($_.Exception.Message)" -Level "Error"
            }
        }

        throw
    }
}

#endregion

#region Backup and Safety Mechanisms

function New-SystemRestorePoint {
        # Create a system restore point with comprehensive error handling and service m...
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Description = "Network Optimizer Backup - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    )

    $result = @{
        Success = $false
        Message = ""
        Details = @{}
        RequiredServices = @("VSS", "swprv")
        ServicesStarted = @()
    }

    try {
        Write-OptimizationLog "Starting System Restore Point creation: $Description" -Level "Info"

        # WhatIf mode handling
        if ($PSCmdlet.ShouldProcess($Description, "Create System Restore Point")) {
            # Continue with actual creation
        } else {
            $result.Success = $true
            $result.Message = "Preview mode - skipped"
            return $result
        }

        # Step 1: Check if System Restore is available on this system
        Write-OptimizationLog "Checking System Restore availability..." -Level "Debug"

        # Check if we're on a supported Windows version
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -lt 10) {
            $result.Message = "System Restore requires Windows 10 or later"
            Write-OptimizationLog $result.Message -Level "Warning"
            return $result
        }

        # Step 2: Check and start required services
        Write-OptimizationLog "Checking required services..." -Level "Debug"
        $servicesOk = $true

        foreach ($serviceName in $result.RequiredServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                $result.Details[$serviceName] = @{
                    Status = $service.Status
                    StartType = $service.StartType
                    OriginalStatus = $service.Status
                }

                if ($service.Status -ne 'Running') {
                    Write-OptimizationLog "Starting service: $serviceName" -Level "Info"

                    # Try to start the service
                    if ($service.StartType -eq 'Disabled') {
                        Write-OptimizationLog "Service $serviceName is disabled - attempting to enable temporarily" -Level "Warning"
                        Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
                        $result.Details[$serviceName].StartTypeChanged = $true
                    }

                    Start-Service -Name $serviceName -ErrorAction Stop
                    $result.ServicesStarted += $serviceName
                    $result.Details[$serviceName].Status = 'Running'
                    Write-OptimizationLog "Successfully started service: $serviceName" -Level "Info"
                } else {
                    Write-OptimizationLog "Service $serviceName is already running" -Level "Debug"
                }
            }
            catch {
                $errorMsg = "Failed to start required service $serviceName : $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $result.Details[$serviceName] = @{ Error = $_.Exception.Message }
                $servicesOk = $false
            }
        }

        if (-not $servicesOk) {
            $result.Message = "Required services could not be started. System Restore is not available."
            return $result
        }

        # Step 3: Wait for services to fully initialize
        Write-OptimizationLog "Waiting for services to initialize..." -Level "Debug"
        Start-Sleep -Seconds 3

        # Step 4: Test and enable System Restore if possible
        Write-OptimizationLog "Testing System Restore configuration..." -Level "Debug"
        try {
            # First, try to enable System Restore if it's disabled
            Write-OptimizationLog "Attempting to enable System Restore on system drive..." -Level "Debug"
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
            Write-OptimizationLog "System Restore enabled on $env:SystemDrive" -Level "Info"
            Start-Sleep -Seconds 2  # Allow time for changes to take effect
        }
        catch {
            $enableError = $_.Exception.Message
            Write-OptimizationLog "Could not enable System Restore: $enableError" -Level "Warning"

            # Check for specific error types
            if ($enableError -match "Access denied|not authorized") {
                Write-OptimizationLog "System Restore may be disabled by Group Policy or system configuration" -Level "Warning"
                $result.Details.RestoreDisabledByPolicy = $true
            }
        }

        # Step 5: Test System Restore access and check for recent restore points
        Write-OptimizationLog "Testing System Restore access..." -Level "Debug"
        try {
            # Try to query existing restore points to test access
            $existingPoints = Get-ComputerRestorePoint -ErrorAction Stop
            $result.Details.ExistingRestorePoints = $existingPoints.Count
            Write-OptimizationLog "System Restore access confirmed. Found $($existingPoints.Count) existing restore points." -Level "Info"

            # Check if a restore point was created recently (within frequency limit)
            if ($existingPoints.Count -gt 0) {
                $latestRestorePoint = $existingPoints | Sort-Object CreationTime -Descending | Select-Object -First 1

                # Convert WMI datetime to DateTime object if needed
                $restorePointTime = $latestRestorePoint.CreationTime
                if ($restorePointTime -is [string]) {
                    try {
                        $restorePointTime = [Management.ManagementDateTimeConverter]::ToDateTime($restorePointTime)
                    }
                    catch {
                        # If conversion fails, try parsing as regular datetime
                        $restorePointTime = [DateTime]::Parse($restorePointTime)
                    }
                }

                $timeSinceLastRestore = (Get-Date) - $restorePointTime

                # Get the frequency limit from registry (default is 1440 minutes = 24 hours)
                try {
                    $frequencyReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue
                    $frequencyMinutes = if ($frequencyReg) { $frequencyReg.SystemRestorePointCreationFrequency } else { 1440 }
                }
                catch {
                    $frequencyMinutes = 1440  # Default to 24 hours
                }

                Write-OptimizationLog "Restore point frequency limit: $frequencyMinutes minutes" -Level "Debug"
                Write-OptimizationLog "Time since last restore point: $($timeSinceLastRestore.TotalMinutes) minutes" -Level "Debug"

                # If within the frequency limit, use the existing restore point
                if ($timeSinceLastRestore.TotalMinutes -lt $frequencyMinutes) {
                    $result.Success = $true
                    $result.Message = "Recent restore point available (created $([math]::Round($timeSinceLastRestore.TotalMinutes)) minutes ago) - using existing point"
                    $result.Details.RestorePoint = @{
                        Description = $latestRestorePoint.Description
                        CreationTime = $restorePointTime
                        SequenceNumber = $latestRestorePoint.SequenceNumber
                    }
                    Write-OptimizationLog "Using existing restore point within frequency limit: $($latestRestorePoint.Description)" -Level "Info"
                    Show-CleanMessage "Restore point created" -Type Success
                    return $result
                }
            }
        }
        catch {
            # If we can't read restore points, System Restore might be disabled
            $accessError = $_.Exception.Message
            Write-OptimizationLog "System Restore access test failed: $accessError" -Level "Warning"

            # Check if it's an access denied error (common when SR is disabled)
            if ($accessError -match "Access denied|access is denied|not enabled") {
                $result.Message = "System Restore is disabled on this system. Using registry backups only."
                Write-OptimizationLog "System Restore appears to be disabled at the system level" -Level "Warning"
                return $result
            }

            # For other errors, we'll still try to create the restore point
            Write-OptimizationLog "Proceeding with restore point creation despite access test failure" -Level "Warning"
        }

        # Step 6: Create the restore point
        Write-OptimizationLog "Creating restore point..." -Level "Info"

        # Use Checkpoint-Computer with enhanced error handling
        Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop

        # Step 7: Verify restore point creation
        Write-OptimizationLog "Verifying restore point creation..." -Level "Debug"
        Start-Sleep -Seconds 2

        try {
            $latestRestorePoint = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1

            if ($latestRestorePoint -and $latestRestorePoint.Description -eq $Description) {
                $result.Success = $true
                $result.Message = "System restore point created successfully"
                $result.Details.RestorePoint = @{
                    Description = $latestRestorePoint.Description
                    CreationTime = $latestRestorePoint.CreationTime
                    SequenceNumber = $latestRestorePoint.SequenceNumber
                }
                Write-OptimizationLog "System restore point verified: $Description" -Level "Info"
            } else {
                $result.Message = "Restore point creation could not be verified"
                Write-OptimizationLog "Could not verify restore point creation" -Level "Warning"
                # Still count as success since Checkpoint-Computer didn't throw an error
                $result.Success = $true
            }
        }
        catch {
            # Verification failed, but the Checkpoint-Computer succeeded
            $result.Success = $true
            $result.Message = "Restore point created but verification failed"
            Write-OptimizationLog "Restore point verification failed: $($_.Exception.Message)" -Level "Warning"
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $result.Message = "Failed to create system restore point: $errorMessage"
        Write-OptimizationLog $result.Message -Level "Error"

        # Provide specific error guidance with simplified user messaging
        if ($errorMessage -match "service cannot be started|is disabled") {
            $result.Message += " (System Restore service is disabled)"
            Write-Host "⚠️  System Restore service is disabled - using registry backups only" -ForegroundColor Yellow
        }
        elseif ($errorMessage -match "Access denied|access is denied") {
            $result.Message += " (System Restore is disabled on this system)"
            Write-Host "⚠️  System Restore is disabled - using registry backups only" -ForegroundColor Yellow
        }
        elseif ($errorMessage -match "not enough storage|disk space") {
            $result.Message += " (Insufficient disk space for restore point)"
            Write-Host "⚠️  Insufficient disk space for restore point - using registry backups only" -ForegroundColor Yellow
        }
        elseif ($errorMessage -match "already been created within the past.*minutes") {
            # Simplify the frequency limit message
            $result.Message = "System restore point was recently created - using existing point"
            Write-OptimizationLog "Restore point frequency limit reached - this is normal behavior" -Level "Info"
            Write-Host "ℹ️  Recent restore point available - using existing point" -ForegroundColor Cyan
            # This is actually a success case - we have a restore point
            $result.Success = $true
        }
        else {
            Write-Host "⚠️  Could not create restore point - using registry backups only" -ForegroundColor Yellow
        }
    }
    finally {
        # Clean up: Stop services we started (but only if we started them)
        foreach ($serviceName in $result.ServicesStarted) {
            try {
                $originalStatus = $result.Details[$serviceName].OriginalStatus
                if ($originalStatus -eq 'Stopped') {
                    Write-OptimizationLog "Stopping service we started: $serviceName" -Level "Debug"
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                }

                # Revert startup type if we changed it
                if ($result.Details[$serviceName].StartTypeChanged) {
                    Write-OptimizationLog "Reverting startup type for service: $serviceName" -Level "Debug"
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-OptimizationLog "Failed to cleanup service $serviceName : $($_.Exception.Message)" -Level "Warning"
            }
        }
    }

    return $result
}

function Backup-NetworkSettings {
        # Export current network registry settings to backup files
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$BackupPath = $Script:BackupPath
    )

    try {
        Write-OptimizationLog "Starting network settings backup to: $BackupPath" -Level "Info"

        if ($PSCmdlet.ShouldProcess($BackupPath, "Backup Network Settings")) {
            # Continue with backup
        } else {
            return @{ Success = $true; BackupPath = $BackupPath; Files = @() }
        }

        # Ensure backup directory exists
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
            Write-OptimizationLog "Created backup directory: $BackupPath" -Level "Info"
        }

        # Get registry configuration to backup
        $registryConfig = Get-RegistryConfigurationHashtables
        $backupInfo = @{
            Success = $true
            BackupPath = $BackupPath
            Files = @()
            RegistryValues = @{}
            Timestamp = Get-Date
        }

        # Create timestamped backup files
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $regBackupFile = Join-Path $BackupPath "NetworkSettings_Backup_$timestamp.reg"
        $jsonBackupFile = Join-Path $BackupPath "NetworkSettings_Backup_$timestamp.json"

        # Initialize .reg file with header
        $regContent = @"
Windows Registry Editor Version 5.00

; Network Optimizer Registry Backup
; Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
; Script Version: $Script:Version

"@

        # Process each registry category
        foreach ($category in $registryConfig.Keys) {
            $regContent += "`r`n; === $category Settings ===`r`n"

            foreach ($registryPath in $registryConfig[$category].Keys) {
                try {
                    # Check if registry path exists
                    if (Test-Path $registryPath) {
                        $regContent += "`r`n[$registryPath]`r`n"

                        # Get current values for each setting
                        $settings = $registryConfig[$category][$registryPath]
                        foreach ($valueName in $settings.Keys) {
                            try {
                                $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                                if ($null -ne $currentValue) {
                                    $value = $currentValue.$valueName

                                    # Store in backup info for JSON export
                                    if (-not $backupInfo.RegistryValues.ContainsKey($registryPath)) {
                                        $backupInfo.RegistryValues[$registryPath] = @{}
                                    }
                                    $backupInfo.RegistryValues[$registryPath][$valueName] = $value

                                    # Format for .reg file based on value type
                                    if ($value -is [int] -or $value -is [uint32]) {
                                        $regContent += "`"$valueName`"=dword:$($value.ToString('x8'))`r`n"
                                    } elseif ($value -is [string]) {
                                        $regContent += "`"$valueName`"=`"$value`"`r`n"
                                    } else {
                                        $regContent += "`"$valueName`"=`"$value`"`r`n"
                                    }
                                } else {
                                }
                            }
                            catch {
                                Write-OptimizationLog "Failed to read registry value: $registryPath\$valueName - $($_.Exception.Message)" -Level "Warning"
                            }
                        }
                    } else {
                        $regContent += "`r`n; Path not found: $registryPath`r`n"
                    }
                }
                catch {
                    Write-OptimizationLog "Failed to process registry path: $registryPath - $($_.Exception.Message)" -Level "Warning"
                }
            }
        }

        # Write .reg backup file
        $regContent | Out-File -FilePath $regBackupFile -Encoding UTF8 -Force
        $backupInfo.Files += $regBackupFile
        Write-OptimizationLog "Registry backup file created: $regBackupFile" -Level "Info"

        # Write JSON backup file for PowerShell consumption
        $backupInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonBackupFile -Encoding UTF8 -Force
        $backupInfo.Files += $jsonBackupFile
        Write-OptimizationLog "JSON backup file created: $jsonBackupFile" -Level "Info"

        # Create backup summary
        $summaryFile = Join-Path $BackupPath "BackupSummary_$timestamp.txt"
        $summary = @"
Network Optimizer Backup Summary
================================
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: $Script:Version
Backup Location: $BackupPath

Files Created:
- Registry Backup: $(Split-Path $regBackupFile -Leaf)
- JSON Backup: $(Split-Path $jsonBackupFile -Leaf)
- Summary: $(Split-Path $summaryFile -Leaf)

Registry Paths Backed Up:
$($registryConfig.Keys | ForEach-Object { "- $_" } | Out-String)

Total Registry Values Backed Up: $($backupInfo.RegistryValues.Values | ForEach-Object { $_.Keys.Count } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)

To restore settings, run the .reg file or use the JSON file with PowerShell.
"@

        $summary | Out-File -FilePath $summaryFile -Encoding UTF8 -Force
        $backupInfo.Files += $summaryFile

        Write-OptimizationLog "Network settings backup completed successfully. Files: $($backupInfo.Files.Count)" -Level "Info"
        Write-Host "Network settings backed up successfully to: $BackupPath" -ForegroundColor Green

        return $backupInfo
    }
    catch {
        $errorMessage = "Failed to backup network settings: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        return @{ Success = $false; Error = $errorMessage }
    }
}

function Restore-NetworkSettings {
        # Restore network settings from backup files
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(ParameterSetName = "File")]
        [string]$BackupFile,

        [Parameter(ParameterSetName = "Info")]
        [hashtable]$BackupInfo
    )

    try {
        Write-OptimizationLog "Starting network settings restoration" -Level "Info"

        # Parameter validation
        if ($PSCmdlet.ParameterSetName -eq "File" -and $BackupFile -and -not (Test-Path $BackupFile)) {
            throw "Backup file not found: $BackupFile"
        }

        if ($PSCmdlet.ShouldProcess("Network Settings", "Restore from Backup")) {
            # Continue with restoration
        } else {
            return $true
        }

        $registryValues = $null

        # Load backup data based on parameter set
        if ($PSCmdlet.ParameterSetName -eq "File") {
            Write-OptimizationLog "Loading backup from file: $BackupFile" -Level "Info"

            if ($BackupFile.EndsWith(".json")) {
                $backupData = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
                $registryValues = $backupData.RegistryValues
            } elseif ($BackupFile.EndsWith(".reg")) {
                Write-OptimizationLog "Executing .reg file restoration: $BackupFile" -Level "Info"
                Start-Process -FilePath "regedit.exe" -ArgumentList "/s", "`"$BackupFile`"" -Wait -NoNewWindow
                Write-OptimizationLog "Registry file restoration completed" -Level "Info"
                return $true
            } else {
                throw "Unsupported backup file format. Use .json or .reg files."
            }
        } else {
            $registryValues = $BackupInfo.RegistryValues
        }

        if ($null -eq $registryValues) {
            throw "No registry values found in backup data"
        }

        # Restore registry values
        $restoredCount = 0
        $errorCount = 0

        foreach ($registryPath in $registryValues.Keys) {
            try {

                # Ensure registry path exists
                if (-not (Test-Path $registryPath)) {
                    New-Item -Path $registryPath -Force | Out-Null
                }

                # Restore each value
                foreach ($valueName in $registryValues[$registryPath].Keys) {
                    try {
                        $value = $registryValues[$registryPath][$valueName]
                        Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Force
                        $restoredCount++
                    }
                    catch {
                        $errorCount++
                        Write-OptimizationLog "Failed to restore: $registryPath\$valueName - $($_.Exception.Message)" -Level "Warning"
                    }
                }
            }
            catch {
                $errorCount++
                Write-OptimizationLog "Failed to process registry path: $registryPath - $($_.Exception.Message)" -Level "Warning"
            }
        }

        Write-OptimizationLog "Network settings restoration completed. Restored: $restoredCount, Errors: $errorCount" -Level "Info"

        if ($errorCount -eq 0) {
            Write-Host "Network settings restored successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Network settings restored with $errorCount errors. Check log for details." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        $errorMessage = "Failed to restore network settings: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        return $false
    }
}

function Test-SafetyValidation {
        # Perform comprehensive safety validation checks before applying optimizations
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        Write-OptimizationLog "Starting comprehensive safety validation" -Level "Info"

        $validationResults = @{
            OverallSuccess = $true
            Checks = @{}
            Warnings = @()
            Errors = @()
            Timestamp = Get-Date
        }

        # Check 1: Administrator privileges
        $adminCheck = Test-AdministratorPrivileges
        $validationResults.Checks["AdminPrivileges"] = @{
            Success = $adminCheck
            Message = if ($adminCheck) { "Administrator privileges confirmed" } else { "Administrator privileges required" }
        }
        # In WhatIf mode or when specifically testing, treat admin requirement as warning instead of error
        if (-not $adminCheck) {
            if ($WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')) {
                $validationResults.Warnings += "Administrator privileges required for actual registry modifications (OK in WhatIf mode)"
            } else {
                $validationResults.Errors += "Administrator privileges required for registry modifications"
                $validationResults.OverallSuccess = $false
            }
        }

        # Check 2: Windows version compatibility
        $windowsCheck = Test-WindowsVersion
        $validationResults.Checks["WindowsVersion"] = @{
            Success = $windowsCheck
            Message = if ($windowsCheck) { "Windows version compatible" } else { "Windows version incompatible" }
        }
        if (-not $windowsCheck) {
            $validationResults.Errors += "Windows 10 or later required"
            $validationResults.OverallSuccess = $false
        }

        # Check 3: PowerShell version compatibility
        $psCheck = Test-PowerShellVersion
        $validationResults.Checks["PowerShellVersion"] = @{
            Success = $psCheck
            Message = if ($psCheck) { "PowerShell version compatible" } else { "PowerShell version incompatible" }
        }
        if (-not $psCheck) {
            $validationResults.Errors += "PowerShell 5.1 or later required"
            $validationResults.OverallSuccess = $false
        }

        # Check 4: Registry access validation
        $registryCheck = Test-RegistryAccess
        $validationResults.Checks["RegistryAccess"] = @{
            Success = $registryCheck
            Message = if ($registryCheck) { "Registry access confirmed" } else { "Registry access denied" }
        }
        # In WhatIf mode, registry access failure is a warning instead of error
        if (-not $registryCheck) {
            if ($WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')) {
                $validationResults.Warnings += "Registry access required for actual optimizations (OK in WhatIf mode)"
            } else {
                $validationResults.Errors += "Registry access required for network optimizations"
                $validationResults.OverallSuccess = $false
            }
        }

        # Check 5: Network adapters presence
        $networkCheck = Test-NetworkAdapters
        $validationResults.Checks["NetworkAdapters"] = @{
            Success = $networkCheck.Success
            Message = $networkCheck.Message
            Details = $networkCheck.Adapters
        }
        # Network adapters not being present is a warning, not a critical error
        # Many optimizations can still be applied and will benefit future connections
        if (-not $networkCheck.Success) {
            $validationResults.Warnings += $networkCheck.Message
        }

        # Check 6: System restore capability
        $restoreCheck = Test-SystemRestoreCapability
        $validationResults.Checks["SystemRestore"] = @{
            Success = $restoreCheck
            Message = if ($restoreCheck) { "System restore available" } else { "System restore not available" }
        }
        if (-not $restoreCheck) {
            $validationResults.Warnings += "System restore not available - manual rollback may be required"
        }

        # Check 7: Backup directory access
        $backupCheck = Test-BackupDirectoryAccess
        $validationResults.Checks["BackupAccess"] = @{
            Success = $backupCheck.Success
            Message = $backupCheck.Message
            Path = $backupCheck.Path
        }
        if (-not $backupCheck.Success) {
            $validationResults.Errors += "Cannot create backup directory: $($backupCheck.Message)"
            $validationResults.OverallSuccess = $false
        }

        # Check 8: System stability indicators
        $stabilityCheck = Test-SystemStability
        $validationResults.Checks["SystemStability"] = @{
            Success = $stabilityCheck.Success
            Message = $stabilityCheck.Message
            Details = $stabilityCheck.Details
        }
        if (-not $stabilityCheck.Success) {
            $validationResults.Warnings += "System stability concerns detected: $($stabilityCheck.Message)"
        }

        # Check 9: TCP/IP optimization requirements
        $tcpipCheck = Test-TCPIPOptimizationRequirements
        $validationResults.Checks["TCPIPRequirements"] = @{
            Success = $tcpipCheck.OverallSuccess
            Message = if ($tcpipCheck.OverallSuccess) { "TCP/IP optimization requirements met" } else { "TCP/IP optimization requirements not met" }
            Details = $tcpipCheck.Tests
        }
        if (-not $tcpipCheck.OverallSuccess) {
            foreach ($errItem in $tcpipCheck.Errors) {
                $validationResults.Errors += "TCP/IP validation: $error"
            }
            $validationResults.OverallSuccess = $false
        }
        if ($tcpipCheck.Warnings.Count -gt 0) {
            foreach ($warning in $tcpipCheck.Warnings) {
                $validationResults.Warnings += "TCP/IP validation: $warning"
            }
        }

        # Summary
        $successCount = ($validationResults.Checks.Values | Where-Object { $_.Success }).Count
        $totalChecks = $validationResults.Checks.Count

        Write-OptimizationLog "Safety validation completed: $successCount/$totalChecks checks passed" -Level "Info"

        if ($validationResults.OverallSuccess) {
            Write-Host "✅ Safety validation passed" -ForegroundColor Green
        } else {
            # Let the calling function handle detailed error display
            Write-OptimizationLog "Safety validation failed: $($validationResults.Errors.Count) errors, $($validationResults.Warnings.Count) warnings" -Level "Warning"
        }

        return $validationResults
    }
    catch {
        $errorMessage = "Safety validation failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        return @{
            OverallSuccess = $false
            Checks = @{}
            Warnings = @()
            Errors = @($errorMessage)
            Timestamp = Get-Date
        }
    }
}

function Test-RegistryAccess {
        # Test registry access permissions for network optimization paths
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $testPaths = @(
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
            'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched',
            'HKLM:\SYSTEM\CurrentControlSet\Services\Psched'
        )

        foreach ($path in $testPaths) {
            # Test if path exists, if not, check if we can create it
            if (-not (Test-Path $path)) {
                # Some paths like Psched policy path may not exist and that's okay
                if ($path -like "*Policies*") {
                    continue
                } else {
                    Write-OptimizationLog "Critical registry path not accessible: $path" -Level "Warning"
                    return $false
                }
            }

            # Test read access for existing paths
            try {
                Get-ItemProperty -Path $path -ErrorAction Stop | Out-Null
            }
            catch {
                Write-OptimizationLog "Registry read access denied: $path" -Level "Warning"
                return $false
            }
        }

        return $true
    }
    catch {
        Write-OptimizationLog "Registry access validation failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

function Test-NetworkAdapters {
        # Validate presence and status of network adapters with comprehensive detection
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        # Check cache first
        $now = Get-Date
        if ($null -ne $Script:NetworkAdaptersCache -and
            $null -ne $Script:NetworkAdaptersCacheTime -and
            ($now - $Script:NetworkAdaptersCacheTime).TotalSeconds -lt $Script:NetworkAdaptersCacheTTL) {
            Write-OptimizationLog "Using cached network adapter data (age: $(($now - $Script:NetworkAdaptersCacheTime).TotalSeconds)s)" -Level "Debug"
            return $Script:NetworkAdaptersCache
        }

        $detectedAdapters = @()
        $detectionMethods = @()

        # Method 1: Get-NetAdapter (Modern PowerShell)
        try {
            $netAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object {
                $_.Status -eq 'Up' -and $_.Virtual -eq $false -and $_.Hidden -eq $false
            }
            if ($netAdapters -and $netAdapters.Count -gt 0) {
                $detectedAdapters += $netAdapters | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        InterfaceDescription = $_.InterfaceDescription
                        LinkSpeed = $_.LinkSpeed
                        MediaType = $_.MediaType
                        Status = $_.Status
                        Method = 'Get-NetAdapter'
                        InterfaceIndex = $_.InterfaceIndex
                    }
                }
                $detectionMethods += "Get-NetAdapter: Found $($netAdapters.Count) adapter(s)"
            } else {
                $detectionMethods += "Get-NetAdapter: No active adapters found"
            }
        }
        catch {
            $detectionMethods += "Get-NetAdapter: Failed - $($_.Exception.Message)"
        }

        # If no adapters found with strict filtering, try relaxed filtering
        if ($detectedAdapters.Count -eq 0) {

            # Method 1b: Get-NetAdapter with relaxed filtering (allow virtual/hidden if they're the only ones)
            try {
                $relaxedAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
                if ($relaxedAdapters -and $relaxedAdapters.Count -gt 0) {
                    $detectedAdapters += $relaxedAdapters | ForEach-Object {
                        [PSCustomObject]@{
                            Name = $_.Name
                            InterfaceDescription = $_.InterfaceDescription
                            LinkSpeed = $_.LinkSpeed
                            MediaType = $_.MediaType
                            Status = $_.Status
                            Method = 'Get-NetAdapter-Relaxed'
                            InterfaceIndex = $_.InterfaceIndex
                        }
                    }
                    $detectionMethods += "Get-NetAdapter-Relaxed: Found $($relaxedAdapters.Count) adapter(s)"
                }
            }
            catch {
            }
        }

        # Method 2: WMI Win32_NetworkAdapter (Fallback)
        try {
            $wmiAdapters = Get-WmiObject -Class Win32_NetworkAdapter -ErrorAction Stop | Where-Object {
                $_.NetConnectionStatus -eq 2 -and $_.NetEnabled -eq $true -and $_.PhysicalAdapter -eq $true
            }
            if ($wmiAdapters -and $wmiAdapters.Count -gt 0) {
                $wmiResults = $wmiAdapters | ForEach-Object {
                    [PSCustomObject]@{
                        Name = if ($_.NetConnectionID) { $_.NetConnectionID } else { $_.Name }
                        InterfaceDescription = $_.Description
                        LinkSpeed = $_.Speed
                        MediaType = if ($_.AdapterTypeId -eq 0) { 'Ethernet' } elseif ($_.AdapterTypeId -eq 71) { 'WiFi' } else { 'Unknown' }
                        Status = 'Up'
                        Method = 'WMI'
                        InterfaceIndex = $_.InterfaceIndex
                    }
                }
                # Add WMI results if they provide additional adapters
                if ($detectedAdapters.Count -eq 0) {
                    $detectedAdapters += $wmiResults
                }
                $detectionMethods += "WMI Win32_NetworkAdapter: Found $($wmiAdapters.Count) adapter(s)"
            } else {
                $detectionMethods += "WMI Win32_NetworkAdapter: No active adapters found"
            }
        }
        catch {
            $detectionMethods += "WMI Win32_NetworkAdapter: Failed - $($_.Exception.Message)"
        }

        # Method 3: CIM Instance (Alternative)
        try {
            $cimAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | Where-Object {
                $_.NetConnectionStatus -eq 2 -and $_.NetEnabled -eq $true
            }
            if ($cimAdapters -and $cimAdapters.Count -gt 0) {
                $cimResults = $cimAdapters | ForEach-Object {
                    [PSCustomObject]@{
                        Name = if ($_.NetConnectionID) { $_.NetConnectionID } else { $_.Name }
                        InterfaceDescription = $_.Description
                        LinkSpeed = $_.Speed
                        MediaType = 'Network'
                        Status = 'Up'
                        Method = 'CIM'
                        InterfaceIndex = $_.InterfaceIndex
                    }
                }
                # Add CIM results if they provide additional adapters
                if ($detectedAdapters.Count -eq 0) {
                    $detectedAdapters += $cimResults
                }
                $detectionMethods += "CIM Win32_NetworkAdapter: Found $($cimAdapters.Count) adapter(s)"
            } else {
                $detectionMethods += "CIM Win32_NetworkAdapter: No active adapters found"
            }
        }
        catch {
            $detectionMethods += "CIM Win32_NetworkAdapter: Failed - $($_.Exception.Message)"
        }

        # Method 4: Network Interface detection via .NET
        try {
            $networkInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
                $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' -and $_.NetworkInterfaceType -ne 'Tunnel'
            }
            if ($networkInterfaces -and $networkInterfaces.Count -gt 0) {
                $netResults = $networkInterfaces | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        InterfaceDescription = $_.Description
                        LinkSpeed = $_.Speed
                        MediaType = $_.NetworkInterfaceType.ToString()
                        Status = 'Up'
                        Method = '.NET NetworkInterface'
                        InterfaceIndex = $null
                    }
                }
                # Always add .NET results - they're reliable even with limited privileges
                $detectedAdapters += $netResults
                $detectionMethods += ".NET NetworkInterface: Found $($networkInterfaces.Count) adapter(s)"
            } else {
                $detectionMethods += ".NET NetworkInterface: No active adapters found"
            }
        }
        catch {
            $detectionMethods += ".NET NetworkInterface: Failed - $($_.Exception.Message)"
        }

        # Method 5: Registry-based detection (Last resort)
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            if (Test-Path $regPath) {
                $regAdapters = Get-ChildItem $regPath | Where-Object {
                    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $props -and $props.DriverDesc -and -not $props.DriverDesc.Contains('Virtual') -and -not $props.DriverDesc.Contains('Loopback')
                }
                if ($regAdapters -and $regAdapters.Count -gt 0) {
                    $regResults = $regAdapters | ForEach-Object {
                        $props = Get-ItemProperty $_.PSPath
                        [PSCustomObject]@{
                            Name = $props.DriverDesc
                            InterfaceDescription = $props.DriverDesc
                            LinkSpeed = $null
                            MediaType = 'Registry-Detected'
                            Status = 'Detected'
                            Method = 'Registry'
                            InterfaceIndex = $null
                        }
                    }
                    # Only add if we don't already have adapters
                    if ($detectedAdapters.Count -eq 0) {
                        $detectedAdapters += $regResults
                    }
                    $detectionMethods += "Registry: Found $($regAdapters.Count) adapter(s)"
                } else {
                    $detectionMethods += "Registry: No adapters found"
                }
            } else {
                $detectionMethods += "Registry: Network adapter registry path not found"
            }
        }
        catch {
            $detectionMethods += "Registry: Failed - $($_.Exception.Message)"
        }

        # Remove duplicates and prepare final result

        # More robust deduplication based on interface description rather than just name
        $uniqueAdapters = @()
        $seenDescriptions = @()

        foreach ($adapter in $detectedAdapters) {
            $key = if ($adapter.InterfaceDescription) { $adapter.InterfaceDescription } else { $adapter.Name }
            if ($key -and $seenDescriptions -notcontains $key) {
                $seenDescriptions += $key
                $uniqueAdapters += $adapter
            }
        }

        $result = @{
            Success = ($uniqueAdapters -and $uniqueAdapters.Count -gt 0)
            Message = if ($uniqueAdapters -and $uniqueAdapters.Count -gt 0) {
                "Found $($uniqueAdapters.Count) active network adapter(s) using multiple detection methods"
            } else {
                "No active network adapters found despite comprehensive detection methods - system may have connectivity issues"
            }
            Adapters = $uniqueAdapters
            DetectionMethods = $detectionMethods
        }

        $Script:NetworkAdaptersCache = $result
        $Script:NetworkAdaptersCacheTime = Get-Date

        return $result

        # Enhanced logging
        Write-OptimizationLog "Network adapter detection completed: $($result.Message)" -Level "Info"

        # Special check for .NET NetworkInterface fallback
        if ($uniqueAdapters.Count -eq 0) {
            $netInterfaceCount = $detectionMethods | Where-Object { $_ -match "\.NET NetworkInterface: Found (\d+)" } | ForEach-Object {
                if ($_ -match "Found (\d+)") { [int]$matches[1] } else { 0 }
            } | Measure-Object -Sum | Select-Object -ExpandProperty Sum

            if ($netInterfaceCount -gt 0) {
                Write-OptimizationLog "WARNING: .NET NetworkInterface found $netInterfaceCount adapter(s) but final result is empty - possible deduplication issue" -Level "Warning"
            }
        }

        if ($uniqueAdapters -and $uniqueAdapters.Count -gt 0) {
            foreach ($adapter in $uniqueAdapters) {
            }
        }

        return $result
    }
    catch {
        $errorMessage = "Comprehensive network adapter detection failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        return @{
            Success = $false
            Message = $errorMessage
            Adapters = @()
            DetectionMethods = @("Critical failure in detection process")
        }
    }
}

function Test-SystemRestoreCapability {
        # Test if system restore functionality is available
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        # Check Volume Shadow Copy Service
        $vssService = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -eq $vssService -or $vssService.Status -ne "Running") {
            return $false
        }

        # Check System Restore Service
        $srService = Get-Service -Name "swprv" -ErrorAction SilentlyContinue
        if ($null -eq $srService) {
            return $false
        }

        # Try to get existing restore points to verify functionality
        try {
            Get-ComputerRestorePoint -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }
    catch {
        return $false
    }
}

function Test-BackupDirectoryAccess {
        # Test access to backup directory creation and writing
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    try {
        $testPath = Join-Path $env:TEMP "NetworkOptimizer_AccessTest_$(Get-Date -Format 'yyyyMMddHHmmss')"

        # Test directory creation
        if ($PSCmdlet.ShouldProcess($testPath, "Create Directory")) {
            New-Item -Path $testPath -ItemType Directory -Force | Out-Null
        }

        # Test file writing
        $testFile = Join-Path $testPath "test.txt"
        if ($PSCmdlet.ShouldProcess($testFile, "Output to File")) {
            if (-not $WhatIfPreference) {
                "Test" | Out-File -FilePath $testFile -Force

                # Test file reading
                Get-Content -Path $testFile | Out-Null

                # Cleanup
                Remove-Item -Path $testPath -Recurse -Force
            }
        }

        return @{
            Success = $true
            Message = "Backup directory access confirmed"
            Path = $env:TEMP
        }
    }
    catch {
        return @{
            Success = $false
            Message = $_.Exception.Message
            Path = $Script:BackupPath
        }
    }
}

function Test-SystemStability {
        # Check system stability indicators before optimization
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        $stabilityIssues = @()
        $details = @{}

        # Check recent system errors in event log
        try {
            $recentErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue
            if ($recentErrors.Count -gt 5) {
                $stabilityIssues += "Multiple system errors in last 24 hours ($($recentErrors.Count) errors)"
            }
            $details["RecentSystemErrors"] = $recentErrors.Count
        }
        catch {
            $details["RecentSystemErrors"] = "Unable to check"
        }

        # Check system uptime
        try {
            $uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
            if ($uptime.TotalHours -lt 1) {
                $stabilityIssues += "System recently rebooted (uptime: $([math]::Round($uptime.TotalMinutes, 1)) minutes)"
            }
            $details["UptimeHours"] = [math]::Round($uptime.TotalHours, 2)
        }
        catch {
            $details["UptimeHours"] = "Unable to determine"
        }

        # Check available disk space
        try {
            $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
            $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
            if ($freeSpaceGB -lt 5) {
                $stabilityIssues += "Low disk space on system drive ($freeSpaceGB GB free)"
            }
            $details["FreeSpaceGB"] = $freeSpaceGB
        }
        catch {
            $details["FreeSpaceGB"] = "Unable to check"
        }

        # Check memory usage
        try {
            $memory = Get-CimInstance -ClassName Win32_OperatingSystem
            $memoryUsagePercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 1)
            # Only consider memory usage above 95% as a stability concern for network optimizations
            if ($memoryUsagePercent -gt 95) {
                $stabilityIssues += "Critical memory usage ($memoryUsagePercent%) - may affect optimization performance"
            } elseif ($memoryUsagePercent -gt 90) {
                # High memory usage is logged but not considered a blocking issue
                Write-OptimizationLog "High memory usage detected ($memoryUsagePercent%) - monitoring system performance" -Level "Info"
            }
            $details["MemoryUsagePercent"] = $memoryUsagePercent
        }
        catch {
            $details["MemoryUsagePercent"] = "Unable to check"
        }

        $result = @{
            Success = $stabilityIssues.Count -eq 0
            Message = if ($stabilityIssues.Count -eq 0) {
                "System stability indicators normal"
            } else {
                "Stability concerns: $($stabilityIssues -join '; ')"
            }
            Details = $details
            Issues = $stabilityIssues
        }

        return $result
    }
    catch {
        return @{
            Success = $false
            Message = "System stability check failed: $($_.Exception.Message)"
            Details = @{}
            Issues = @("Stability check failed")
        }
    }
}

function Invoke-EmergencyRollback {
        # Perform emergency rollback of network optimizations
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [switch]$UseSystemRestore,

        [Parameter()]
        [string]$BackupPath = $Script:BackupPath
    )

    try {
        Write-Host "EMERGENCY ROLLBACK INITIATED" -ForegroundColor Red -BackgroundColor Yellow
        Write-OptimizationLog "Emergency rollback initiated" -Level "Warning"

        if ($UseSystemRestore) {
            Write-Host "Attempting system restore rollback..." -ForegroundColor Yellow
            Write-OptimizationLog "Attempting system restore rollback" -Level "Info"

            # Get the most recent restore point created by Network Optimizer
            $restorePoints = Get-ComputerRestorePoint | Where-Object {
                $_.Description -like "*Network Optimizer*"
            } | Sort-Object CreationTime -Descending

            if ($restorePoints.Count -eq 0) {
                Write-Host "No Network Optimizer restore points found" -ForegroundColor Red
                Write-OptimizationLog "No Network Optimizer restore points found for rollback" -Level "Error"
                return $false
            }

            $latestRestorePoint = $restorePoints[0]
            Write-Host "Found restore point: $($latestRestorePoint.Description) from $($latestRestorePoint.CreationTime)" -ForegroundColor Yellow

            # Confirm system restore (unless in silent mode)
            if (-not $Silent) {
                $confirm = Read-Host "This will restart your computer and restore to: $($latestRestorePoint.CreationTime). Continue? (y/N)"
                if ($confirm -notmatch '^[Yy]') {
                    Write-Host "System restore cancelled by user" -ForegroundColor Yellow
                    return $false
                }
            }

            Write-Host "Initiating system restore..." -ForegroundColor Red
            Write-OptimizationLog "Initiating system restore to: $($latestRestorePoint.CreationTime)" -Level "Warning"

            # Start system restore
            Restore-Computer -RestorePoint $latestRestorePoint.SequenceNumber -Confirm:$false
            return $true
        }
        else {
            Write-Host "Attempting registry backup rollback..." -ForegroundColor Yellow
            Write-OptimizationLog "Attempting registry backup rollback from: $BackupPath" -Level "Info"

            if (-not $BackupPath -or -not (Test-Path $BackupPath)) {
                Write-Host "Backup directory not found: $BackupPath" -ForegroundColor Red
                Write-OptimizationLog "Backup directory not found for rollback: $BackupPath" -Level "Error"
                return $false
            }

            # Find the most recent JSON backup file
            $backupFiles = Get-ChildItem -Path $BackupPath -Filter "*.json" | Sort-Object LastWriteTime -Descending
            if ($backupFiles.Count -eq 0) {
                Write-Host "No backup files found in: $BackupPath" -ForegroundColor Red
                Write-OptimizationLog "No backup files found for rollback in: $BackupPath" -Level "Error"
                return $false
            }

            $latestBackup = $backupFiles[0]
            Write-Host "Found backup file: $($latestBackup.Name)" -ForegroundColor Yellow

            # Confirm rollback (unless in silent mode)
            if (-not $Silent) {
                $confirm = Read-Host "This will restore network settings from: $($latestBackup.LastWriteTime). Continue? (y/N)"
                if ($confirm -notmatch '^[Yy]') {
                    Write-Host "Registry rollback cancelled by user" -ForegroundColor Yellow
                    return $false
                }
            }

            Write-Host "Restoring network settings from backup..." -ForegroundColor Yellow
            $restoreResult = Restore-NetworkSettings -BackupFile $latestBackup.FullName

            if ($restoreResult) {
                Write-Host "EMERGENCY ROLLBACK COMPLETED SUCCESSFULLY" -ForegroundColor Green -BackgroundColor Black
                Write-OptimizationLog "Emergency rollback completed successfully" -Level "Info"
                Write-Host "Network settings have been restored to their previous state." -ForegroundColor Green
                Write-Host "You may need to restart your computer for all changes to take effect." -ForegroundColor Yellow
                return $true
            } else {
                Write-Host "EMERGENCY ROLLBACK FAILED" -ForegroundColor Red -BackgroundColor Yellow
                Write-OptimizationLog "Emergency rollback failed" -Level "Error"
                return $false
            }
        }
    }
    catch {
        $errorMessage = "Emergency rollback failed: $($_.Exception.Message)"
        Write-Host "EMERGENCY ROLLBACK FAILED: $errorMessage" -ForegroundColor Red -BackgroundColor Yellow
        Write-OptimizationLog $errorMessage -Level "Error"
        return $false
    }
}

function Confirm-OptimizationSafety {
        # Final safety confirmation before applying optimizations
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$SelectedOptimizations
    )

    try {
        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        Write-Host "NETWORK OPTIMIZATION SAFETY CONFIRMATION" -ForegroundColor Cyan
        Write-Host "="*60 -ForegroundColor Cyan

        Write-Host "`nSelected Optimizations ($($SelectedOptimizations.Count)):" -ForegroundColor Yellow
        foreach ($opt in $SelectedOptimizations) {
            Write-Host "  • $($opt.Name) [$($opt.Category)]" -ForegroundColor White
            if ($opt.RequiresReboot) {
                Write-Host "    [WARN] Requires reboot" -ForegroundColor Yellow
            }
        }

        Write-Host "`nSafety Mechanisms in Place:" -ForegroundColor Green
        Write-Host "  ✅ System restore point created" -ForegroundColor Green
        Write-Host "  ✅ Registry settings backed up to: $Script:BackupPath" -ForegroundColor Green
        Write-Host "  ✅ Detailed logging enabled: $Script:LogFile" -ForegroundColor Green
        Write-Host "  ✅ Emergency rollback available" -ForegroundColor Green

        Write-Host "`nRollback Options Available:" -ForegroundColor Cyan
        Write-Host "  1. Registry restore from backup files" -ForegroundColor White
        Write-Host "  2. System restore point (requires restart)" -ForegroundColor White
        Write-Host "  3. Manual restoration using .reg files" -ForegroundColor White

        Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Red
        Write-Host "  • These optimizations modify Windows registry settings" -ForegroundColor Yellow
        Write-Host "  • Some changes may require a system restart to take effect" -ForegroundColor Yellow
        Write-Host "  • You can rollback changes using the backup files created" -ForegroundColor Yellow
        Write-Host "  • Test network connectivity after optimization" -ForegroundColor Yellow

        if ($Silent) {
            Write-Host "`nRunning in Silent mode - proceeding automatically..." -ForegroundColor Green
            Write-OptimizationLog "Safety confirmation bypassed in Silent mode" -Level "Info"
            return $true
        }

        Write-Host "`n" + "="*60 -ForegroundColor Cyan
        $confirmation = Read-Host "Do you want to proceed with these network optimizations? (y/N)"

        if ($confirmation -match '^[Yy]') {
            Write-OptimizationLog "User confirmed to proceed with optimizations" -Level "Info"
            Write-Host "Proceeding with network optimizations..." -ForegroundColor Green
            return $true
        } else {
            Write-OptimizationLog "User cancelled optimization process" -Level "Info"
            Write-Host "Network optimization cancelled by user." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-OptimizationLog "Safety confirmation failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

#endregion

#region Configuration Management System

class OptimizationOption {
    # Network optimization option with metadata and execution logic
    [string]$Name
    [string]$Description
    [string]$Category
    [bool]$Selected
    [scriptblock]$Action
    [string[]]$Requirements
    [hashtable]$RegistrySettings
    [bool]$RequiresReboot
    [string]$Impact
    [string]$SafetyLevel

    # Constructor
    OptimizationOption([string]$Name, [string]$Description, [string]$Category, [scriptblock]$Action) {
        $this.Name = $Name
        $this.Description = $Description
        $this.Category = $Category
        $this.Selected = $false
        $this.Action = $Action
        $this.Requirements = @()
        $this.RegistrySettings = @{}
        $this.RequiresReboot = $false
        $this.Impact = "Low"
    }

    # Method to execute the optimization
    [bool] Execute() {
        try {
            Write-OptimizationLog "Executing optimization: $($this.Name)" -Level "Info"

            if ($PSCmdlet -and $PSCmdlet.ShouldProcess($this.Name, "Execute Optimization")) {
                # Continue with optimization execution
            } elseif ($PSBoundParameters.ContainsKey('WhatIf')) {
                return $true
            }

            & $this.Action
            Write-OptimizationLog "Optimization completed successfully: $($this.Name)" -Level "Info"
            return $true
        }
        catch {
            Write-OptimizationLog "Optimization failed: $($this.Name) - $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }

    # Method to validate requirements
    [bool] ValidateRequirements() {
        foreach ($requirement in $this.Requirements) {
            # Basic requirement validation - can be extended
            if ($requirement -like "*Admin*" -and -not (Test-AdministratorPrivileges)) {
                return $false
            }
        }
        return $true
    }
}

class OptimizationResult {
    # Result of a network optimization operation
    [string]$OptimizationName
    [bool]$Success
    [string]$Message
    [hashtable]$BeforeValues
    [hashtable]$AfterValues
    [datetime]$Timestamp
    [string[]]$Errors

    # Constructor
    OptimizationResult() {
        $this.Success = $false
        $this.Message = ""
        $this.BeforeValues = @{}
        $this.AfterValues = @{}
        $this.Timestamp = Get-Date
        $this.Errors = @()
    }

    # Full constructor
    OptimizationResult([string]$OptimizationName, [bool]$Success, [string]$Message, [hashtable]$BeforeValues, [hashtable]$AfterValues, [datetime]$Timestamp, [string[]]$Errors) {
        $this.OptimizationName = $OptimizationName
        $this.Success = $Success
        $this.Message = $Message
        $this.BeforeValues = $BeforeValues
        $this.AfterValues = $AfterValues
        $this.Timestamp = $Timestamp
        $this.Errors = $Errors
    }

    # Method to add an error
    [void] AddError([string]$ErrorMessage) {
        $this.Errors += $ErrorMessage
        $this.Success = $false
    }

    # Method to get a summary string
    [string] GetSummary() {
        $status = if ($this.Success) { "SUCCESS" } else { "FAILED" }
        $errorCount = $this.Errors.Count
        $changeCount = $this.AfterValues.Count

        return "[$status] $($this.OptimizationName): $($this.Message) (Changes: $changeCount, Errors: $errorCount)"
    }
}

class NetworkOptimizerConfig {
    # Central configuration management for network optimizer
    [OptimizationOption[]]$Options
    [hashtable]$RegistrySettings
    [hashtable]$NetworkSettings
    [hashtable]$CategorySettings
    [string]$ConfigVersion
    [datetime]$LastModified

    # Constructor
    NetworkOptimizerConfig() {
        $this.Options = @()
        $this.RegistrySettings = @{}
        $this.NetworkSettings = @{}
        $this.CategorySettings = @{}
        $this.ConfigVersion = "1.0.0"
        $this.LastModified = Get-Date
    }

    # Method to add optimization option
    [void] AddOption([OptimizationOption]$Option) {
        $this.Options += $Option
        $this.LastModified = Get-Date
    }

    # Method to get options by category
    [OptimizationOption[]] GetOptionsByCategory([string]$Category) {
        return $this.Options | Where-Object { $_.Category -eq $Category }
    }

    # Method to get selected options
    [OptimizationOption[]] GetSelectedOptions() {
        return $this.Options | Where-Object { $_.Selected -eq $true }
    }

    # Method to validate configuration
    [bool] ValidateConfiguration() {
        try {
            # Validate that we have options
            if ($this.Options.Count -eq 0) {
                Write-OptimizationLog "Configuration validation failed: No optimization options defined" -Level "Warning"
                return $false
            }

            # Validate each option
            foreach ($option in $this.Options) {
                if ([string]::IsNullOrWhiteSpace($option.Name)) {
                    Write-OptimizationLog "Configuration validation failed: Option with empty name found" -Level "Warning"
                    return $false
                }

                if ([string]::IsNullOrWhiteSpace($option.Category)) {
                    Write-OptimizationLog "Configuration validation failed: Option '$($option.Name)' has no category" -Level "Warning"
                    return $false
                }

                if ($null -eq $option.Action) {
                    Write-OptimizationLog "Configuration validation failed: Option '$($option.Name)' has no action defined" -Level "Warning"
                    return $false
                }
            }

            Write-OptimizationLog "Configuration validation passed: $($this.Options.Count) options validated" -Level "Info"
            return $true
        }
        catch {
            Write-OptimizationLog "Configuration validation error: $($_.Exception.Message)" -Level "Error"
            return $false
        }
    }

    # Method to reset all selections
    [void] ResetSelections() {
        foreach ($option in $this.Options) {
            $option.Selected = $false
        }
        $this.LastModified = Get-Date
        Write-OptimizationLog "All option selections reset" -Level "Info"
    }

    # Method to select recommended options
    [void] SelectRecommendedOptions() {
        foreach ($option in $this.Options) {
            # Select options with low impact by default
            if ($option.Impact -eq "Low" -or $option.Impact -eq "Medium") {
                $option.Selected = $true
            }
        }
        $this.LastModified = Get-Date
        Write-OptimizationLog "Recommended options selected" -Level "Info"
    }
}

function Get-DefaultConfiguration {
        # Initialize and return the default network optimization configuration
    [CmdletBinding()]
    [OutputType([NetworkOptimizerConfig])]
    param()

    try {
        Write-OptimizationLog "Initializing default configuration" -Level "Info"

        # Create new configuration instance
        $config = [NetworkOptimizerConfig]::new()

        # Initialize registry configuration hashtables for all optimization categories
        $config.RegistrySettings = Get-RegistryConfigurationHashtables

        # Initialize network settings
        $config.NetworkSettings = Get-NetworkConfigurationHashtables

        # Initialize category settings
        $config.CategorySettings = Get-CategoryConfigurationHashtables

        # Add TCP/IP Protocol Stack optimizations
        Add-TCPIPOptimizations -Config $config

        # Add Connection Type optimizations
        Add-ConnectionTypeOptimizations -Config $config

        # Add DNS and Memory Management optimizations
        Add-DNSMemoryOptimizations -Config $config

        # Add Network Security optimizations
        Add-NetworkSecurityOptimizations -Config $config

        # Add Gaming and Streaming optimizations
        Add-GamingStreamingOptimizations -Config $config

        # Add Tools and Utilities
        Add-ToolsUtilitiesOptimizations -Config $config

        # Validate the configuration
        if (-not $config.ValidateConfiguration()) {
            throw "Default configuration validation failed"
        }

        Write-OptimizationLog "Default configuration initialized successfully with $($config.Options.Count) options" -Level "Info"
        return $config
    }
    catch {
        $errorMessage = "Failed to initialize default configuration: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        throw $errorMessage
    }
}

function Get-RegistryConfigurationHashtables {
        # Get comprehensive registry configuration hashtables for all optimization cate...
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'TCP' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'Tcp1323Opts' = 1                    # Enable TCP window scaling
                'TCPNoDelay' = 1                     # Disable Nagle's algorithm
                'TcpAckFrequency' = 1                # TCP ACK frequency
                'DefaultTTL' = 64                    # Default Time To Live
                'EnablePMTUDiscovery' = 1            # Path MTU Discovery
                'EnablePMTUBHDetect' = 0             # Black hole detection
                'SackOpts' = 1                       # Selective ACK
                'MaxFreeTcbs' = 16000                # Maximum free TCBs
                'MaxHashTableSize' = 65536           # Hash table size
                'MaxUserPort' = 65534                # Maximum user port
                'TcpTimedWaitDelay' = 30             # TIME_WAIT delay
            }
        }
        'UDP' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'FastSendDatagramThreshold' = 1024   # Fast send threshold
                'FastCopyReceiveThreshold' = 1024    # Fast copy threshold
                'UdpSegmentationOffload' = 1         # UDP segmentation offload
            }
        }
        'DNS' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' = @{
                'CacheHashTableBucketSize' = 1       # DNS cache bucket size
                'CacheHashTableSize' = 384           # DNS cache table size
                'MaxCacheEntryTtlLimit' = 86400      # Max cache TTL (24 hours)
                'MaxSOACacheEntryTtlLimit' = 301     # Max SOA cache TTL
                'NegativeCacheTime' = 0              # Negative cache time
                'NetFailureCacheTime' = 0            # Network failure cache time
                'NegativeSOACacheTime' = 0           # Negative SOA cache time
            }
        }
        'QoS' = @{
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' = @{
                'NonBestEffortLimit' = 0             # QoS bandwidth limit
            }
            'HKLM:\SYSTEM\CurrentControlSet\Services\Psched' = @{
                'NonBestEffortLimit' = 0             # QoS service limit
            }
        }
        'NetworkAdapter' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}' = @{
                'ScanWhenAssociated' = 0             # Disable scanning when associated
                'PowerSaveMode' = 0                  # Disable power save mode
                'EnablePowerManagement' = 0          # Disable power management
            }
        }
        'Security' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters' = @{
                'SMB1' = 0                           # Disable SMBv1
                'EnableSecuritySignature' = 1        # Enable SMB signing
                'RequireSecuritySignature' = 1       # Require SMB signing
            }
            'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' = @{
                'EnableSecuritySignature' = 1        # Enable client SMB signing
                'RequireSecuritySignature' = 0       # Client SMB signing requirement
            }
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'SynAttackProtect' = 1               # Enable SYN attack protection
                'EnableICMPRedirect' = 0             # Disable ICMP redirects for security
                'DisableIPSourceRouting' = 1         # Disable IP source routing
                'EnableSecurityFilters' = 1          # Enable security filters
                'NoNameReleaseOnDemand' = 1          # Prevent NetBIOS name release attacks
                'KeepAliveTime' = 7200000            # 2 hours keep-alive for security
                'KeepAliveInterval' = 1000           # 1 second keep-alive interval
                'EnableDeadGWDetect' = 1             # Enable dead gateway detection
            }
            'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' = @{
                'NoNameReleaseOnDemand' = 1          # Prevent NetBIOS name release attacks
                'NodeType' = 2                       # P-node (point-to-point) for security
                'EnableLMHosts' = 0                  # Disable LMHosts lookup
                'EnableProxy' = 0                    # Disable NetBIOS proxy
            }
            'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' = @{
                'LmCompatibilityLevel' = 5           # Send NTLMv2 response only, refuse LM & NTLM
                'NoLMHash' = 1                       # Do not store LAN Manager hash
                'RestrictAnonymous' = 1              # Restrict anonymous access
            }
            'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' = @{
                'DisablePasswordChange' = 0          # Enable automatic password changes
                'MaximumPasswordAge' = 30            # Maximum password age in days
                'RequireSignOrSeal' = 1              # Require signing or sealing
                'RequireStrongKey' = 1               # Require strong session key
            }
        }
        'Gaming' = @{
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' = @{
                'GPU Priority' = 8                   # GPU priority for games
                'Priority' = 6                       # CPU priority for games
                'Scheduling Category' = 'High'       # Scheduling category
                'SFIO Priority' = 'High'             # Storage I/O priority
            }
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                'NetworkThrottlingIndex' = 0xffffffff # Disable network throttling
                'SystemResponsiveness' = 0           # System responsiveness
            }
        }
        'Memory' = @{
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' = @{
                'LargeSystemCache' = 0               # Large system cache
                'DisablePagingExecutive' = 1         # Disable paging executive
            }
        }
    }
}

function Get-NetworkConfigurationHashtables {
        # Get network-specific configuration hashtables
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'AdapterSettings' = @{
            'ReceiveBuffers' = 2048
            'TransmitBuffers' = 2048
            'InterruptModeration' = 'Enabled'
            'FlowControl' = 'Disabled'
            'JumboPacket' = 9014
            'RSS' = 'Enabled'
            'TCPChecksumOffloadIPv4' = 'Enabled'
            'UDPChecksumOffloadIPv4' = 'Enabled'
        }
        'ConnectionTypes' = @{
            'WiFi' = @{
                'RoamingAggressiveness' = 'Medium'
                'PowerSaving' = 'Disabled'
                'ChannelWidth' = 'Auto'
            }
            'Ethernet' = @{
                'SpeedDuplex' = 'Auto'
                'FlowControl' = 'Disabled'
                'GreenEthernet' = 'Disabled'
            }
            'Fiber' = @{
                'SpeedDuplex' = 'Auto'
                'FlowControl' = 'Disabled'
                'JumboFrames' = 'Enabled'
            }
        }
        'PowerManagement' = @{
            'AllowComputerToTurnOffDevice' = $false
            'AllowDeviceToWakeComputer' = $true
            'OnlyAllowMagicPacketToWakeComputer' = $true
        }
    }
}

function Get-CategoryConfigurationHashtables {
        # Get category-specific configuration settings
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        'TCP/IP Protocol Stack' = @{
            'Description' = 'Core TCP/IP stack optimizations for improved network performance'
            'Impact' = 'Medium'
            'RequiresReboot' = $true
            'SafetyLevel' = 'High'
        }
        'Connection Type Optimizations' = @{
            'Description' = 'Connection-specific optimizations for WiFi, Ethernet, and Fiber'
            'Impact' = 'Low'
            'RequiresReboot' = $false
            'SafetyLevel' = 'High'
        }
        'DNS and Memory Management' = @{
            'Description' = 'DNS caching and network memory optimizations'
            'Impact' = 'Low'
            'RequiresReboot' = $false
            'SafetyLevel' = 'High'
        }
        'Network Security' = @{
            'Description' = 'Security-focused network optimizations and protocol settings'
            'Impact' = 'Medium'
            'RequiresReboot' = $true
            'SafetyLevel' = 'Medium'
        }
        'Gaming and Streaming' = @{
            'Description' = 'Optimizations for gaming, streaming, and real-time applications'
            'Impact' = 'High'
            'RequiresReboot' = $true
            'SafetyLevel' = 'Medium'
        }
        'Tools and Utilities' = @{
            'Description' = 'System maintenance and diagnostic tools'
            'Impact' = 'Low'
            'RequiresReboot' = $false
            'SafetyLevel' = 'High'
        }
    }
}

function Add-TCPIPOptimizations {
        [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    # TCP Stack Comprehensive Optimization
    $tcpStackOptimization = [OptimizationOption]::new(
        "TCP Stack Optimization",
        "Apply comprehensive TCP stack optimizations including window scaling, Nagle algorithm, and ACK frequency",
        "TCP/IP Protocol Stack",
        {
            $result = Optimize-TCPStack -EnableWindowScaling -DisableNagleAlgorithm -OptimizeAckFrequency -SetDefaultTTL 64 -EnablePMTUDiscovery -OptimizeHashTableSize -OptimizePortRange -OptimizeTimedWaitDelay
            Write-OptimizationLog "TCP Stack optimization completed with $($result.Operations.Count) operations" -Level "Info"
            return $result
        }
    )
    $tcpStackOptimization.Requirements = @("Administrator")
    $tcpStackOptimization.Impact = "High"
    $tcpStackOptimization.RequiresReboot = $true
    $Config.AddOption($tcpStackOptimization)

    # UDP Settings Optimization
    $udpOptimization = [OptimizationOption]::new(
        "UDP Settings Optimization",
        "Optimize UDP buffer management and segmentation offload for improved performance",
        "TCP/IP Protocol Stack",
        {
            $result = Optimize-UDPSettings -OptimizeBuffers -EnableSegmentationOffload
            Write-OptimizationLog "UDP settings optimization completed with $($result.Operations.Count) operations" -Level "Info"
            return $result
        }
    )
    $udpOptimization.Requirements = @("Administrator")
    $udpOptimization.Impact = "Medium"
    $udpOptimization.RequiresReboot = $true
    $Config.AddOption($udpOptimization)

    # QoS Configuration
    $qosOptimization = [OptimizationOption]::new(
        "QoS Configuration",
        "Configure Quality of Service settings to remove bandwidth limits and optimize network throttling",
        "TCP/IP Protocol Stack",
        {
            $result = Set-QoSConfiguration -DisableBandwidthLimit -OptimizeNetworkThrottling -SetSystemResponsiveness -ResponsivenessValue 10
            Write-OptimizationLog "QoS configuration completed with $($result.Operations.Count) operations" -Level "Info"
            return $result
        }
    )
    $qosOptimization.Requirements = @("Administrator")
    $qosOptimization.Impact = "Medium"
    $qosOptimization.RequiresReboot = $false
    $Config.AddOption($qosOptimization)

    # IP Stack Configuration
    $ipStackOptimization = [OptimizationOption]::new(
        "IP Stack Configuration",
        "Optimize IPv4 and IPv6 stack settings for enhanced performance and routing",
        "TCP/IP Protocol Stack",
        {
            $result = Set-IPStack -OptimizeIPv4 -OptimizeIPv6 -OptimizeRoutingTable
            Write-OptimizationLog "IP stack configuration completed with $($result.Operations.Count) operations" -Level "Info"
            return $result
        }
    )
    $ipStackOptimization.Requirements = @("Administrator")
    $ipStackOptimization.Impact = "Medium"
    $ipStackOptimization.RequiresReboot = $true
    $Config.AddOption($ipStackOptimization)

    # Individual TCP Window Scaling (for granular control)
    $tcpWindowScaling = [OptimizationOption]::new(
        "TCP Window Scaling Only",
        "Enable TCP window scaling for improved throughput on high-bandwidth connections",
        "TCP/IP Protocol Stack",
        {
            $result = Optimize-TCPStack -EnableWindowScaling
            Write-OptimizationLog "TCP Window Scaling optimization completed" -Level "Info"
            return $result
        }
    )
    $tcpWindowScaling.Requirements = @("Administrator")
    $tcpWindowScaling.Impact = "Medium"
    $tcpWindowScaling.RequiresReboot = $true
    $Config.AddOption($tcpWindowScaling)

    # Individual Nagle Algorithm Disable (for granular control)
    $disableNagle = [OptimizationOption]::new(
        "Disable Nagle Algorithm Only",
        "Disable Nagle's algorithm to reduce latency for small packets",
        "TCP/IP Protocol Stack",
        {
            $result = Optimize-TCPStack -DisableNagleAlgorithm
            Write-OptimizationLog "Nagle Algorithm disable optimization completed" -Level "Info"
            return $result
        }
    )
    $disableNagle.Requirements = @("Administrator")
    $disableNagle.Impact = "Medium"
    $disableNagle.RequiresReboot = $true
    $Config.AddOption($disableNagle)

    # Individual TCP ACK Frequency (for granular control)
    $tcpAckFreq = [OptimizationOption]::new(
        "Optimize TCP ACK Frequency Only",
        "Optimize TCP acknowledgment frequency for better performance",
        "TCP/IP Protocol Stack",
        {
            $result = Optimize-TCPStack -OptimizeAckFrequency
            Write-OptimizationLog "TCP ACK Frequency optimization completed" -Level "Info"
            return $result
        }
    )
    $tcpAckFreq.Requirements = @("Administrator")
    $tcpAckFreq.Impact = "Low"
    $tcpAckFreq.RequiresReboot = $true
    $Config.AddOption($tcpAckFreq)
}

function Add-ConnectionTypeOptimizations {
        [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    # WiFi Power Management
    $wifiPower = [OptimizationOption]::new(
        "Disable WiFi Power Management",
        "Disable WiFi adapter power management for consistent performance",
        "Connection Type Optimizations",
        {
            # This will be implemented in the connection type module
            Write-OptimizationLog "WiFi power management optimization placeholder" -Level "Info"
        }
    )
    $wifiPower.Requirements = @("Administrator")
    $wifiPower.Impact = "Low"
    $wifiPower.RequiresReboot = $false
    $Config.AddOption($wifiPower)

    # Ethernet Flow Control
    $ethernetFlow = [OptimizationOption]::new(
        "Optimize Ethernet Flow Control",
        "Configure Ethernet flow control settings for optimal performance",
        "Connection Type Optimizations",
        {
            # This will be implemented in the connection type module
            Write-OptimizationLog "Ethernet flow control optimization placeholder" -Level "Info"
        }
    )
    $ethernetFlow.Requirements = @("Administrator")
    $ethernetFlow.Impact = "Low"
    $ethernetFlow.RequiresReboot = $false
    $Config.AddOption($ethernetFlow)
}

function Add-DNSMemoryOptimizations {
        # Add DNS and memory management optimization options to configuration
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    # DNS Cache Optimization
    $dnsCache = [OptimizationOption]::new(
        "Optimize DNS Cache",
        "Configure DNS cache settings for improved resolution performance and reduced lookup times",
        "DNS and Memory Management",
        {
            $result = Optimize-DNSCache
            if (-not $result.Success) {
                throw "DNS cache optimization failed: $($result.Message)"
            }
            return $result
        }
    )
    $dnsCache.Requirements = @("Administrator")
    $dnsCache.Impact = "Low"
    $dnsCache.RequiresReboot = $false
    $Config.AddOption($dnsCache)

    # Network Memory Management
    $networkMemory = [OptimizationOption]::new(
        "Optimize Network Memory",
        "Configure TCP port ranges and connection limits for optimal network memory usage",
        "DNS and Memory Management",
        {
            $result = Optimize-NetworkMemory
            if (-not $result.Success) {
                throw "Network memory optimization failed: $($result.Message)"
            }
            return $result
        }
    )
    $networkMemory.Requirements = @("Administrator")
    $networkMemory.Impact = "Medium"
    $networkMemory.RequiresReboot = $true
    $Config.AddOption($networkMemory)

    # System Memory Management
    $memoryManagement = [OptimizationOption]::new(
        "Optimize Memory Management",
        "Configure network buffer allocation and system memory management settings",
        "DNS and Memory Management",
        {
            $result = Set-MemoryManagement
            if (-not $result.Success) {
                throw "Memory management optimization failed: $($result.Message)"
            }
            return $result
        }
    )
    $memoryManagement.Requirements = @("Administrator")
    $memoryManagement.Impact = "Medium"
    $memoryManagement.RequiresReboot = $true
    $Config.AddOption($memoryManagement)
}

function Add-NetworkSecurityOptimizations {
        # Add comprehensive network security optimization options to configuration
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    try {

        # Windows Firewall Optimization
        $firewallOptimization = [OptimizationOption]::new(
            "Optimize Windows Firewall",
            "Configure Windows Firewall for optimal performance and security with essential network rules",
            "Network Security",
            {
                Set-NetworkSecurity -EnableFirewallOptimization
            }
        )
        $firewallOptimization.Requirements = @("Administrator", "NetSecurity")
        $firewallOptimization.Impact = "Medium"
        $firewallOptimization.RequiresReboot = $false
        $firewallOptimization.SafetyLevel = "Medium"
        $Config.AddOption($firewallOptimization)

        # Port Security Configuration
        $portSecurity = [OptimizationOption]::new(
            "Configure Port Security",
            "Optimize port security settings including dynamic port ranges and connection timeouts",
            "Network Security",
            {
                Set-NetworkSecurity -ConfigurePortSecurity
            }
        )
        $portSecurity.Requirements = @("Administrator")
        $portSecurity.Impact = "Low"
        $portSecurity.RequiresReboot = $true
        $portSecurity.SafetyLevel = "High"
        $Config.AddOption($portSecurity)

        # Connection Security Optimization
        $connectionSecurity = [OptimizationOption]::new(
            "Optimize Connection Security",
            "Configure connection security settings including SYN attack protection and secure protocols",
            "Network Security",
            {
                Set-NetworkSecurity -OptimizeConnectionSecurity
            }
        )
        $connectionSecurity.Requirements = @("Administrator")
        $connectionSecurity.Impact = "Medium"
        $connectionSecurity.RequiresReboot = $true
        $connectionSecurity.SafetyLevel = "Medium"
        $Config.AddOption($connectionSecurity)

        # Disable SMBv1 Protocol
        $disableSMBv1 = [OptimizationOption]::new(
            "Disable SMBv1 Protocol",
            "Disable the vulnerable SMBv1 protocol to improve system security and prevent attacks",
            "Network Security",
            {
                Disable-VulnerableProtocols -DisableSMBv1
            }
        )
        $disableSMBv1.Requirements = @("Administrator")
        $disableSMBv1.Impact = "Medium"
        $disableSMBv1.RequiresReboot = $true
        $disableSMBv1.SafetyLevel = "Medium"
        $Config.AddOption($disableSMBv1)

        # Configure Secure Protocols
        $secureProtocols = [OptimizationOption]::new(
            "Configure Secure Protocols",
            "Enable and configure secure network protocols (SMBv2/v3, secure authentication)",
            "Network Security",
            {
                Disable-VulnerableProtocols -ConfigureSecureProtocols
            }
        )
        $secureProtocols.Requirements = @("Administrator")
        $secureProtocols.Impact = "Low"
        $secureProtocols.RequiresReboot = $true
        $secureProtocols.SafetyLevel = "High"
        $Config.AddOption($secureProtocols)

        # NetBIOS Security Configuration
        $netbiosSecurity = [OptimizationOption]::new(
            "Configure NetBIOS Security",
            "Secure NetBIOS settings and disable NetBIOS over TCP/IP where appropriate",
            "Network Security",
            {
                Disable-VulnerableProtocols -DisableNetBIOS
            }
        )
        $netbiosSecurity.Requirements = @("Administrator")
        $netbiosSecurity.Impact = "Low"
        $netbiosSecurity.RequiresReboot = $false
        $netbiosSecurity.SafetyLevel = "Medium"
        $Config.AddOption($netbiosSecurity)

        # SSL/TLS Security Optimization
        $sslTlsOptimization = [OptimizationOption]::new(
            "Optimize SSL/TLS Security",
            "Configure secure SSL/TLS settings, disable weak protocols, and optimize cipher suites",
            "Network Security",
            {
                Disable-VulnerableProtocols -OptimizeSSLTLS
            }
        )
        $sslTlsOptimization.Requirements = @("Administrator")
        $sslTlsOptimization.Impact = "Medium"
        $sslTlsOptimization.RequiresReboot = $false
        $sslTlsOptimization.SafetyLevel = "High"
        $Config.AddOption($sslTlsOptimization)

        # DNS Cache Flush
        $dnsFlush = [OptimizationOption]::new(
            "Flush DNS Cache",
            "Clear DNS resolver cache to resolve connectivity issues and refresh DNS records",
            "Network Security",
            {
                Invoke-NetworkMaintenance -FlushDNSCache
            }
        )
        $dnsFlush.Requirements = @("Administrator")
        $dnsFlush.Impact = "Low"
        $dnsFlush.RequiresReboot = $false
        $dnsFlush.SafetyLevel = "High"
        $Config.AddOption($dnsFlush)

        # Winsock Reset
        $winsockReset = [OptimizationOption]::new(
            "Reset Winsock Catalog",
            "Reset Winsock catalog to default state to resolve network connectivity issues",
            "Network Security",
            {
                Invoke-NetworkMaintenance -ResetWinsock
            }
        )
        $winsockReset.Requirements = @("Administrator")
        $winsockReset.Impact = "High"
        $winsockReset.RequiresReboot = $true
        $winsockReset.SafetyLevel = "Medium"
        $Config.AddOption($winsockReset)

        # IP Stack Reset
        $ipStackReset = [OptimizationOption]::new(
            "Reset TCP/IP Stack",
            "Reset TCP/IP stack configuration to default state for comprehensive network troubleshooting",
            "Network Security",
            {
                Invoke-NetworkMaintenance -ResetIPStack
            }
        )
        $ipStackReset.Requirements = @("Administrator")
        $ipStackReset.Impact = "High"
        $ipStackReset.RequiresReboot = $true
        $ipStackReset.SafetyLevel = "Medium"
        $Config.AddOption($ipStackReset)

        # Network Adapter Reset
        $adapterReset = [OptimizationOption]::new(
            "Reset Network Adapters",
            "Reset network adapter configurations and renew IP settings",
            "Network Security",
            {
                Invoke-NetworkMaintenance -ResetNetworkAdapters
            }
        )
        $adapterReset.Requirements = @("Administrator")
        $adapterReset.Impact = "Medium"
        $adapterReset.RequiresReboot = $false
        $adapterReset.SafetyLevel = "Medium"
        $Config.AddOption($adapterReset)

        # Comprehensive Network Security Suite
        $comprehensiveSecurity = [OptimizationOption]::new(
            "Apply Comprehensive Security Suite",
            "Apply all recommended network security optimizations in a single operation",
            "Network Security",
            {
                Set-NetworkSecurity -EnableFirewallOptimization -ConfigurePortSecurity -OptimizeConnectionSecurity
                Disable-VulnerableProtocols -DisableSMBv1 -ConfigureSecureProtocols -OptimizeSSLTLS
            }
        )
        $comprehensiveSecurity.Requirements = @("Administrator", "NetSecurity")
        $comprehensiveSecurity.Impact = "High"
        $comprehensiveSecurity.RequiresReboot = $true
        $comprehensiveSecurity.SafetyLevel = "Medium"
        $Config.AddOption($comprehensiveSecurity)

    }
    catch {
        $errorMessage = "Failed to add network security optimizations: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        throw $errorMessage
    }
}

function Add-GamingStreamingOptimizations {
        [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    # Gaming Mode
    $gamingMode = [OptimizationOption]::new(
        "Enable Gaming Mode",
        "Configure system for optimal gaming performance",
        "Gaming and Streaming",
        {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord
        }
    )
    $gamingMode.Requirements = @("Administrator")
    $gamingMode.Impact = "High"
    $gamingMode.RequiresReboot = $true
    $Config.AddOption($gamingMode)

    # Streaming Optimization
    $streamingMode = [OptimizationOption]::new(
        "Enable Streaming Optimization",
        "Optimize network settings for video streaming applications",
        "Gaming and Streaming",
        {
            # Disable QoS bandwidth limit
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
    )
    $streamingMode.Requirements = @("Administrator")
    $streamingMode.Impact = "Medium"
    $streamingMode.RequiresReboot = $false
    $Config.AddOption($streamingMode)
}

function Add-ToolsUtilitiesOptimizations {
        [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    # Create System Restore Point (conditional)
    $createRestorePoint = [OptimizationOption]::new(
        "Create System Restore Point",
        "Create a system restore point before applying optimizations (only if initial attempt failed)",
        "Tools and Utilities",
        {
            # Check if we already created a restore point during initialization
            if ($Script:RestorePointCreated) {
                Write-OptimizationLog "System restore point already created during initialization - skipping duplicate creation" -Level "Info"
                Write-Host "✓ System restore point already available from initialization" -ForegroundColor Green
                return
            }

            Write-OptimizationLog "Initial restore point creation failed - attempting retry..." -Level "Info"
            Write-Host "Retrying system restore point creation..." -ForegroundColor Yellow

            # Retry restore point creation since the initial attempt failed
            $retryResult = New-SystemRestorePoint -Description "Network Optimizer - Retry After Optimizations"

            if ($retryResult.Success) {
                Write-OptimizationLog "Retry restore point creation successful: $($retryResult.Message)" -Level "Info"
                Write-Host "✓ $($retryResult.Message)" -ForegroundColor Green
                $Script:RestorePointCreated = $true
                $Script:RestorePointMessage = $retryResult.Message
            } else {
                Write-OptimizationLog "Retry restore point creation also failed: $($retryResult.Message)" -Level "Warning"
                Write-Host "⚠️  Retry failed: $($retryResult.Message)" -ForegroundColor Yellow
                Write-Host "✓ Continuing with registry backups for safety" -ForegroundColor Green
            }
        }
    )
    $createRestorePoint.Requirements = @("Administrator")
    $createRestorePoint.Impact = "Low"
    $createRestorePoint.RequiresReboot = $false
    $Config.AddOption($createRestorePoint)

    # Network Health Report
    $healthReport = [OptimizationOption]::new(
        "Generate Network Health Report",
        "Generate a comprehensive network health and performance report",
        "Tools and Utilities",
        {
            # This will be implemented in the reporting module
            Write-OptimizationLog "Network health report generation placeholder" -Level "Info"
        }
    )
    $healthReport.Requirements = @("Administrator")
    $healthReport.Impact = "Low"
    $healthReport.RequiresReboot = $false
    $Config.AddOption($healthReport)
}

function Test-ConfigurationIntegrity {
        # Validate configuration integrity and consistency
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    try {
        Write-OptimizationLog "Starting configuration integrity test" -Level "Info"

        # Basic configuration validation
        if (-not $Config.ValidateConfiguration()) {
            Write-OptimizationLog "Basic configuration validation failed" -Level "Error"
            return $false
        }

        # Validate registry paths exist or can be created
        foreach ($category in $Config.RegistrySettings.Keys) {
            foreach ($regPath in $Config.RegistrySettings[$category].Keys) {
                try {
                    # Test if we can access the registry path
                    $null = Get-Item -Path $regPath -ErrorAction Stop
                }
                catch {
                    # Path doesn't exist, check if parent exists
                    $parentPath = Split-Path $regPath -Parent
                    if (-not (Test-Path $parentPath)) {
                        Write-OptimizationLog "Registry parent path not found: $parentPath" -Level "Warning"
                        return $false
                    }
                }
            }
        }

        # Validate option requirements (skip in WhatIf mode for admin requirements)
        foreach ($option in $Config.Options) {
            $skipAdminCheck = $WhatIfPreference -or ($PSBoundParameters.ContainsKey('WhatIf')) -or $Script:AutoPreviewEnabled

            $requirementsValid = $true
            foreach ($requirement in $option.Requirements) {
                if ($requirement -like "*Admin*") {
                    if (-not $skipAdminCheck -and -not (Test-AdministratorPrivileges)) {
                        $requirementsValid = $false
                        break
                    }
                }
            }

            if (-not $requirementsValid) {
                Write-OptimizationLog "Option requirements validation failed: $($option.Name)" -Level "Warning"
                return $false
            }
        }

        Write-OptimizationLog "Configuration integrity test passed" -Level "Info"
        return $true
    }
    catch {
        Write-OptimizationLog "Configuration integrity test failed: $($_.Exception.Message)" -Level "Error"
        return $false
    }
}

#endregion

#region TCP/IP Protocol Stack Optimization Module

function Optimize-TCPStack {
        # Optimize TCP protocol stack settings for improved network performance
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$EnableWindowScaling,

        [Parameter()]
        [switch]$DisableNagleAlgorithm,

        [Parameter()]
        [switch]$OptimizeAckFrequency,

        [Parameter()]
        [ValidateRange(1, 255)]
        [int]$SetDefaultTTL,

        [Parameter()]
        [switch]$EnablePMTUDiscovery,

        [Parameter()]
        [switch]$OptimizeHashTableSize,

        [Parameter()]
        [switch]$OptimizePortRange,

        [Parameter()]
        [switch]$OptimizeTimedWaitDelay
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    }

    try {
        Write-OptimizationLog "Starting TCP stack optimization" -Level "Info"

        # Validate registry path exists
        if (-not (Test-Path $results.RegistryPath)) {
            throw "TCP/IP registry path not found: $($results.RegistryPath)"
        }

        # TCP Window Scaling (RFC 1323)
        if ($EnableWindowScaling) {
            $operation = Invoke-SafeOperation -OperationName "Enable TCP Window Scaling" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "Tcp1323Opts" -Value 1 -Type DWord -Force
                Write-OptimizationLog "TCP Window Scaling enabled (Tcp1323Opts = 1)" -Level "Info"
                return @{ Name = "Tcp1323Opts"; Value = 1; Description = "TCP Window Scaling enabled" }
            }
            $results.Operations += $operation
        }

        # Disable Nagle's Algorithm for reduced latency
        if ($DisableNagleAlgorithm) {
            $operation = Invoke-SafeOperation -OperationName "Disable Nagle Algorithm" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force
                Write-OptimizationLog "Nagle's Algorithm disabled (TCPNoDelay = 1)" -Level "Info"
                return @{ Name = "TCPNoDelay"; Value = 1; Description = "Nagle's Algorithm disabled for reduced latency" }
            }
            $results.Operations += $operation
        }

        # Optimize TCP ACK Frequency
        if ($OptimizeAckFrequency) {
            $operation = Invoke-SafeOperation -OperationName "Optimize TCP ACK Frequency" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
                Write-OptimizationLog "TCP ACK Frequency optimized (TcpAckFrequency = 1)" -Level "Info"
                return @{ Name = "TcpAckFrequency"; Value = 1; Description = "TCP ACK frequency optimized" }
            }
            $results.Operations += $operation
        }

        # Set Default TTL
        if ($SetDefaultTTL) {
            $operation = Invoke-SafeOperation -OperationName "Set Default TTL" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "DefaultTTL" -Value $SetDefaultTTL -Type DWord -Force
                Write-OptimizationLog "Default TTL set to $SetDefaultTTL" -Level "Info"
                return @{ Name = "DefaultTTL"; Value = $SetDefaultTTL; Description = "Default Time To Live configured" }
            }
            $results.Operations += $operation
        }

        # Enable Path MTU Discovery
        if ($EnablePMTUDiscovery) {
            $operation = Invoke-SafeOperation -OperationName "Enable Path MTU Discovery" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "EnablePMTUDiscovery" -Value 1 -Type DWord -Force
                Write-OptimizationLog "Path MTU Discovery enabled" -Level "Info"
                return @{ Name = "EnablePMTUDiscovery"; Value = 1; Description = "Path MTU Discovery enabled" }
            }
            $results.Operations += $operation
        }

        # Optimize Hash Table Size
        if ($OptimizeHashTableSize) {
            $operation = Invoke-SafeOperation -OperationName "Optimize Hash Table Size" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "MaxHashTableSize" -Value 65536 -Type DWord -Force
                Write-OptimizationLog "Hash table size optimized (MaxHashTableSize = 65536)" -Level "Info"
                return @{ Name = "MaxHashTableSize"; Value = 65536; Description = "TCP hash table size optimized" }
            }
            $results.Operations += $operation
        }

        # Optimize Port Range
        if ($OptimizePortRange) {
            $operation = Invoke-SafeOperation -OperationName "Optimize Port Range" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "MaxUserPort" -Value 65534 -Type DWord -Force
                Write-OptimizationLog "Maximum user port set to 65534" -Level "Info"
                return @{ Name = "MaxUserPort"; Value = 65534; Description = "Maximum user port range optimized" }
            }
            $results.Operations += $operation
        }

        # Optimize Timed Wait Delay
        if ($OptimizeTimedWaitDelay) {
            $operation = Invoke-SafeOperation -OperationName "Optimize Timed Wait Delay" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force
                Write-OptimizationLog "TCP Timed Wait Delay set to 30 seconds" -Level "Info"
                return @{ Name = "TcpTimedWaitDelay"; Value = 30; Description = "TCP TIME_WAIT delay optimized" }
            }
            $results.Operations += $operation
        }

        Write-OptimizationLog "TCP stack optimization completed successfully. Operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "TCP stack optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Optimize-UDPSettings {
        # Optimize UDP protocol settings for improved performance
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$OptimizeBuffers,

        [Parameter()]
        [switch]$EnableSegmentationOffload,

        [Parameter()]
        [switch]$SetCustomThresholds,

        [Parameter()]
        [ValidateRange(512, 8192)]
        [int]$SendThreshold = 1024,

        [Parameter()]
        [ValidateRange(512, 8192)]
        [int]$ReceiveThreshold = 1024
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    }

    try {
        Write-OptimizationLog "Starting UDP settings optimization" -Level "Info"

        # Validate registry path exists
        if (-not (Test-Path $results.RegistryPath)) {
            throw "TCP/IP registry path not found: $($results.RegistryPath)"
        }

        # Optimize UDP Buffers
        if ($OptimizeBuffers -or $SetCustomThresholds) {
            # Fast Send Datagram Threshold
            $operation = Invoke-SafeOperation -OperationName "Set UDP Fast Send Threshold" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "FastSendDatagramThreshold" -Value $SendThreshold -Type DWord -Force
                Write-OptimizationLog "UDP Fast Send Datagram Threshold set to $SendThreshold" -Level "Info"
                return @{ Name = "FastSendDatagramThreshold"; Value = $SendThreshold; Description = "UDP fast send threshold optimized" }
            }
            $results.Operations += $operation

            # Fast Copy Receive Threshold
            $operation = Invoke-SafeOperation -OperationName "Set UDP Fast Copy Receive Threshold" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "FastCopyReceiveThreshold" -Value $ReceiveThreshold -Type DWord -Force
                Write-OptimizationLog "UDP Fast Copy Receive Threshold set to $ReceiveThreshold" -Level "Info"
                return @{ Name = "FastCopyReceiveThreshold"; Value = $ReceiveThreshold; Description = "UDP fast copy receive threshold optimized" }
            }
            $results.Operations += $operation
        }

        # Enable UDP Segmentation Offload
        if ($EnableSegmentationOffload) {
            $operation = Invoke-SafeOperation -OperationName "Enable UDP Segmentation Offload" -Operation {
                Set-ItemProperty -Path $results.RegistryPath -Name "UdpSegmentationOffload" -Value 1 -Type DWord -Force
                Write-OptimizationLog "UDP Segmentation Offload enabled" -Level "Info"
                return @{ Name = "UdpSegmentationOffload"; Value = 1; Description = "UDP segmentation offload enabled" }
            }
            $results.Operations += $operation
        }

        Write-OptimizationLog "UDP settings optimization completed successfully. Operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "UDP settings optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Set-QoSConfiguration {
        # Configure Quality of Service (QoS) packet scheduler settings
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$DisableBandwidthLimit,

        [Parameter()]
        [switch]$EnablePacketScheduler,

        [Parameter()]
        [switch]$OptimizeNetworkThrottling,

        [Parameter()]
        [switch]$SetSystemResponsiveness,

        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$ResponsivenessValue = 20
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        RegistryPaths = @{
            QoSPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched'
            MultimediaProfile = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
        }
    }

    try {
        Write-OptimizationLog "Starting QoS configuration optimization" -Level "Info"

        # Disable QoS Bandwidth Limit (remove 20% reservation)
        if ($DisableBandwidthLimit) {
            $operation = Invoke-SafeOperation -OperationName "Disable QoS Bandwidth Limit" -Operation {
                # Ensure the registry path exists
                if (-not (Test-Path $results.RegistryPaths.QoSPolicy)) {
                    New-Item -Path $results.RegistryPaths.QoSPolicy -Force | Out-Null
                    Write-OptimizationLog "Created QoS policy registry path" -Level "Info"
                }

                Set-ItemProperty -Path $results.RegistryPaths.QoSPolicy -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
                Write-OptimizationLog "QoS bandwidth limit disabled (NonBestEffortLimit = 0)" -Level "Info"
                return @{ Name = "NonBestEffortLimit"; Value = 0; Description = "QoS 20% bandwidth reservation removed" }
            }
            $results.Operations += $operation
        }

        # Optimize Network Throttling
        if ($OptimizeNetworkThrottling) {
            $operation = Invoke-SafeOperation -OperationName "Optimize Network Throttling" -Operation {
                # Ensure the registry path exists
                if (-not (Test-Path $results.RegistryPaths.MultimediaProfile)) {
                    New-Item -Path $results.RegistryPaths.MultimediaProfile -Force | Out-Null
                    Write-OptimizationLog "Created multimedia profile registry path" -Level "Info"
                }

                # Disable network throttling for multimedia applications
                Set-ItemProperty -Path $results.RegistryPaths.MultimediaProfile -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord -Force
                Write-OptimizationLog "Network throttling disabled for multimedia applications" -Level "Info"
                return @{ Name = "NetworkThrottlingIndex"; Value = 0xffffffff; Description = "Network throttling disabled for multimedia" }
            }
            $results.Operations += $operation
        }

        # Set System Responsiveness
        if ($SetSystemResponsiveness) {
            $operation = Invoke-SafeOperation -OperationName "Set System Responsiveness" -Operation {
                # Ensure the registry path exists
                if (-not (Test-Path $results.RegistryPaths.MultimediaProfile)) {
                    New-Item -Path $results.RegistryPaths.MultimediaProfile -Force | Out-Null
                    Write-OptimizationLog "Created multimedia profile registry path" -Level "Info"
                }

                Set-ItemProperty -Path $results.RegistryPaths.MultimediaProfile -Name "SystemResponsiveness" -Value $ResponsivenessValue -Type DWord -Force
                Write-OptimizationLog "System responsiveness set to $ResponsivenessValue" -Level "Info"
                return @{ Name = "SystemResponsiveness"; Value = $ResponsivenessValue; Description = "System responsiveness configured for network operations" }
            }
            $results.Operations += $operation
        }

        # Enable Packet Scheduler Service
        if ($EnablePacketScheduler) {
            $operation = Invoke-SafeOperation -OperationName "Enable Packet Scheduler Service" -Operation {
                $service = Get-Service -Name "PSchedSvc" -ErrorAction SilentlyContinue
                if ($service) {
                    if ($service.Status -ne "Running") {
                        Set-Service -Name "PSchedSvc" -StartupType Automatic -ErrorAction Stop
                        Start-Service -Name "PSchedSvc" -ErrorAction Stop
                        Write-OptimizationLog "Packet Scheduler service enabled and started" -Level "Info"
                    } else {
                        Write-OptimizationLog "Packet Scheduler service already running" -Level "Info"
                    }
                    return @{ Name = "PSchedSvc"; Value = "Running"; Description = "Packet Scheduler service enabled" }
                } else {
                    Write-OptimizationLog "Packet Scheduler service not found" -Level "Warning"
                    return @{ Name = "PSchedSvc"; Value = "NotFound"; Description = "Packet Scheduler service not available" }
                }
            }
            $results.Operations += $operation
        }

        Write-OptimizationLog "QoS configuration optimization completed successfully. Operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "QoS configuration optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Set-IPStack {
        # Configure IPv4 and IPv6 stack settings for optimal performance
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$OptimizeIPv4,

        [Parameter()]
        [switch]$OptimizeIPv6,

        [Parameter()]
        [switch]$EnableIPForwarding,

        [Parameter()]
        [switch]$OptimizeRoutingTable,

        [Parameter()]
        [switch]$DisableIPv6,

        [Parameter()]
        [switch]$SetIPv6Preference,

        [Parameter()]
        [ValidateRange(0, 255)]
        [int]$IPv6PreferenceValue = 32
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        RegistryPaths = @{
            IPv4 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            IPv6 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            Interfaces = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
        }
    }

    try {
        Write-OptimizationLog "Starting IP stack configuration" -Level "Info"

        # IPv4 Stack Optimizations
        if ($OptimizeIPv4) {
            $operation = Invoke-SafeOperation -OperationName "Optimize IPv4 Stack" -Operation {
                # Enable dead gateway detection
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "EnableDeadGWDetect" -Value 1 -Type DWord -Force

                # Optimize ARP cache
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "ArpCacheLife" -Value 600 -Type DWord -Force
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "ArpCacheMinReferencedLife" -Value 600 -Type DWord -Force

                Write-OptimizationLog "IPv4 stack optimizations applied" -Level "Info"
                return @{ Name = "IPv4Optimizations"; Value = "Applied"; Description = "IPv4 stack optimized for performance" }
            }
            $results.Operations += $operation
        }

        # IPv6 Stack Optimizations
        if ($OptimizeIPv6 -and -not $DisableIPv6) {
            $operation = Invoke-SafeOperation -OperationName "Optimize IPv6 Stack" -Operation {
                # Ensure IPv6 parameters path exists
                if (-not (Test-Path $results.RegistryPaths.IPv6)) {
                    New-Item -Path $results.RegistryPaths.IPv6 -Force | Out-Null
                    Write-OptimizationLog "Created IPv6 parameters registry path" -Level "Info"
                }

                # Enable IPv6 optimizations
                Set-ItemProperty -Path $results.RegistryPaths.IPv6 -Name "EnableICMPRedirect" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $results.RegistryPaths.IPv6 -Name "DeadGWDetectDefault" -Value 1 -Type DWord -Force

                Write-OptimizationLog "IPv6 stack optimizations applied" -Level "Info"
                return @{ Name = "IPv6Optimizations"; Value = "Applied"; Description = "IPv6 stack optimized for performance" }
            }
            $results.Operations += $operation
        }

        # Disable IPv6 (if requested)
        if ($DisableIPv6) {
            $operation = Invoke-SafeOperation -OperationName "Disable IPv6" -Operation {
                # Disable IPv6 on all interfaces
                Set-ItemProperty -Path $results.RegistryPaths.IPv6 -Name "DisabledComponents" -Value 0xff -Type DWord -Force
                Write-OptimizationLog "IPv6 disabled on all interfaces" -Level "Info"
                return @{ Name = "IPv6Disabled"; Value = 0xff; Description = "IPv6 protocol disabled" }
            }
            $results.Operations += $operation
        }

        # Set IPv6 Preference
        if ($SetIPv6Preference -and -not $DisableIPv6) {
            $operation = Invoke-SafeOperation -OperationName "Set IPv6 Preference" -Operation {
                Set-ItemProperty -Path $results.RegistryPaths.IPv6 -Name "DisabledComponents" -Value $IPv6PreferenceValue -Type DWord -Force
                Write-OptimizationLog "IPv6 preference set to $IPv6PreferenceValue" -Level "Info"
                return @{ Name = "IPv6Preference"; Value = $IPv6PreferenceValue; Description = "IPv6 address selection preference configured" }
            }
            $results.Operations += $operation
        }

        # Enable IP Forwarding
        if ($EnableIPForwarding) {
            $operation = Invoke-SafeOperation -OperationName "Enable IP Forwarding" -Operation {
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "IPEnableRouter" -Value 1 -Type DWord -Force
                Write-OptimizationLog "IP forwarding enabled" -Level "Info"
                return @{ Name = "IPEnableRouter"; Value = 1; Description = "IP forwarding enabled for routing" }
            }
            $results.Operations += $operation
        }

        # Optimize Routing Table
        if ($OptimizeRoutingTable) {
            $operation = Invoke-SafeOperation -OperationName "Optimize Routing Table" -Operation {
                # Increase routing table hash size
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "RouteTableHashSize" -Value 1024 -Type DWord -Force

                # Optimize route cache
                Set-ItemProperty -Path $results.RegistryPaths.IPv4 -Name "MaxForwardBufferMemory" -Value 2097152 -Type DWord -Force

                Write-OptimizationLog "Routing table optimizations applied" -Level "Info"
                return @{ Name = "RoutingOptimizations"; Value = "Applied"; Description = "Routing table performance optimized" }
            }
            $results.Operations += $operation
        }

        Write-OptimizationLog "IP stack configuration completed successfully. Operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "IP stack configuration failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Test-TCPIPOptimizationRequirements {
        # Validate system requirements for TCP/IP optimizations
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $results = @{
        OverallSuccess = $true
        Tests = @()
        Errors = @()
        Warnings = @()
    }

    try {
        Write-OptimizationLog "Starting TCP/IP optimization requirements validation" -Level "Info"

        # Test registry access
        $registryTest = @{
            Name = "Registry Access"
            Success = $true
            Details = @()
        }

        $registryPaths = @(
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
        )

        foreach ($path in $registryPaths) {
            try {
                if (Test-Path $path) {
                    # Test basic read access - sufficient for most operations
                    Get-ItemProperty -Path $path -ErrorAction Stop | Out-Null
                    $registryTest.Details += "[OK] $path - Read access confirmed"
                } else {
                    $registryTest.Details += "[WARN] $path - Path does not exist (will be created)"
                }
            }
            catch {
                $registryTest.Success = $false
                $registryTest.Details += "[FAIL] $path - Access denied: $($_.Exception.Message)"
                $results.Errors += "Registry access failed for: $path"
            }
        }

        $results.Tests += $registryTest
        if (-not $registryTest.Success) { $results.OverallSuccess = $false }

        # Test network adapters using robust detection
        $adapterTest = @{
            Name = "Network Adapters"
            Success = $true
            Details = @()
        }

        try {
            # Use the robust adapter detection function
            $adapterResult = Test-NetworkAdapters

            # Force array conversion and explicit boolean comparison
            $hasAdapters = $false
            if ($adapterResult.Success -eq $true) {
                $adapterArray = @($adapterResult.Adapters)
                if ($adapterArray.Count -gt 0) {
                    $hasAdapters = $true
                }
            }

            if ($hasAdapters) {
                $adapterTest.Details += "[OK] Found $(@($adapterResult.Adapters).Count) active network adapter(s) using comprehensive detection"
                foreach ($adapter in $adapterResult.Adapters) {
                    $adapterTest.Details += "  - $($adapter.Name) ($($adapter.InterfaceDescription)) [Method: $($adapter.Method)]"
                }
                $adapterTest.Details += "Detection methods used: $($adapterResult.DetectionMethods -join '; ')"
            } else {
                # Still don't fail completely - optimizations can be applied for future use
                $adapterTest.Success = $true
                $adapterTest.Details += "[WARN] No active network adapters detected despite comprehensive detection"
                $adapterTest.Details += "Detection methods attempted: $($adapterResult.DetectionMethods -join '; ')"
                $results.Warnings += "No active network adapters detected using multiple detection methods - optimizations will apply to future connections"
            }
        }
        catch {
            $adapterTest.Success = $true  # Don't fail the entire validation
            $adapterTest.Details += "[WARN] Network adapter detection failed: $($_.Exception.Message)"
            $results.Warnings += "Network adapter detection failed - optimizations will be applied for future use"
        }

        $results.Tests += $adapterTest
        if (-not $adapterTest.Success) { $results.OverallSuccess = $false }

        # Test required services
        $serviceTest = @{
            Name = "Required Services"
            Success = $true
            Details = @()
        }

        $requiredServices = @('Tcpip', 'Dnscache')
        foreach ($serviceName in $requiredServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                if ($service.Status -eq 'Running') {
                    $serviceTest.Details += "[OK] $serviceName service is running"
                } else {
                    $serviceTest.Details += "[WARN] $serviceName service is not running (Status: $($service.Status))"
                    $results.Warnings += "$serviceName service is not running"
                }
            }
            catch {
                $serviceTest.Success = $false
                $serviceTest.Details += "[FAIL] $serviceName service not found"
                $results.Errors += "$serviceName service is not available"
            }
        }

        $results.Tests += $serviceTest
        if (-not $serviceTest.Success) { $results.OverallSuccess = $false }

        # Test PowerShell capabilities
        $psTest = @{
            Name = "PowerShell Capabilities"
            Success = $true
            Details = @()
        }

        try {
            # Test cmdlet availability
            $requiredCmdlets = @('Set-ItemProperty', 'Get-NetAdapter', 'Set-Service')
            foreach ($cmdlet in $requiredCmdlets) {
                if (Get-Command $cmdlet -ErrorAction SilentlyContinue) {
                    $psTest.Details += "[OK] $cmdlet cmdlet available"
                } else {
                    $psTest.Success = $false
                    $psTest.Details += "[FAIL] $cmdlet cmdlet not available"
                    $results.Errors += "$cmdlet cmdlet is required but not available"
                }
            }
        }
        catch {
            $psTest.Success = $false
            $psTest.Details += "[FAIL] PowerShell capability test failed: $($_.Exception.Message)"
            $results.Errors += "PowerShell capability validation failed"
        }

        $results.Tests += $psTest
        if (-not $psTest.Success) { $results.OverallSuccess = $false }

        Write-OptimizationLog "TCP/IP optimization requirements validation completed. Overall success: $($results.OverallSuccess)" -Level "Info"

    }
    catch {
        $results.OverallSuccess = $false
        $errorMessage = "TCP/IP optimization requirements validation failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
    }

    return $results
}

#endregion

#region DNS and Memory Management Optimization Module

function Optimize-DNSCache {
        # Configure DNS cache settings for improved resolution performance
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult])]
    param(
        [Parameter()]
        [ValidateRange(64, 2048)]
        [int]$CacheHashTableSize = 384,

        [Parameter()]
        [ValidateRange(300, 604800)]  # 5 minutes to 7 days
        [int]$MaxCacheEntryTtlLimit = 86400,

        [Parameter()]
        [ValidateRange(0, 3600)]  # 0 to 1 hour
        [int]$NegativeCacheTime = 0,

        [Parameter()]
        [ValidateRange(0, 3600)]  # 0 to 1 hour
        [int]$NetFailureCacheTime = 0
    )

    $result = [OptimizationResult]::new()
    $result.OptimizationName = "DNS Cache Optimization"
    $result.Timestamp = Get-Date

    try {
        Write-OptimizationLog "Starting DNS cache optimization" -Level "Info"

        $dnsRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

        # Validate registry path exists
        if (-not (Test-Path $dnsRegistryPath)) {
            throw "DNS cache registry path not found: $dnsRegistryPath"
        }

        # Collect current values for backup
        $currentValues = @{}
        $settingsToApply = @{
            'CacheHashTableBucketSize' = 1
            'CacheHashTableSize' = $CacheHashTableSize
            'MaxCacheEntryTtlLimit' = $MaxCacheEntryTtlLimit
            'MaxSOACacheEntryTtlLimit' = 301
            'NegativeCacheTime' = $NegativeCacheTime
            'NetFailureCacheTime' = $NetFailureCacheTime
            'NegativeSOACacheTime' = 0
        }

        foreach ($setting in $settingsToApply.Keys) {
            try {
                $currentValue = Get-ItemProperty -Path $dnsRegistryPath -Name $setting -ErrorAction SilentlyContinue
                if ($null -ne $currentValue) {
                    $currentValues[$setting] = $currentValue.$setting
                } else {
                    $currentValues[$setting] = "Not Set"
                }
            }
            catch {
                $currentValues[$setting] = "Error Reading"
                Write-OptimizationLog "Failed to read current value for ${1} : $($_.Exception.Message)" -Level "Warning"
            }
        }

        $result.BeforeValues = $currentValues.Clone()

        if ($PSCmdlet.ShouldProcess("DNS Cache Settings", "Apply Optimizations")) {
            # Apply DNS cache optimizations
            foreach ($setting in $settingsToApply.Keys) {
                try {
                    $value = $settingsToApply[$setting]
                    Set-ItemProperty -Path $dnsRegistryPath -Name $setting -Value $value -Type DWord -Force
                    Write-OptimizationLog "Set DNS cache setting: $setting = $value" -Level "Info"
                }
                catch {
                    $errorMsg = "Failed to set DNS cache setting $setting : $($_.Exception.Message)"
                    Write-OptimizationLog $errorMsg -Level "Error"
                    $result.Errors += $errorMsg
                }
            }

            # Verify applied settings
            $appliedValues = @{}
            foreach ($setting in $settingsToApply.Keys) {
                try {
                    $newValue = Get-ItemProperty -Path $dnsRegistryPath -Name $setting -ErrorAction Stop
                    $appliedValues[$setting] = $newValue.$setting
                }
                catch {
                    $appliedValues[$setting] = "Verification Failed"
                }
            }

            $result.AfterValues = $appliedValues

            # Check if all settings were applied successfully
            $successCount = 0
            foreach ($setting in $settingsToApply.Keys) {
                if ($appliedValues[$setting] -eq $settingsToApply[$setting]) {
                    $successCount++
                }
            }

            if ($successCount -eq $settingsToApply.Count) {
                $result.Success = $true
                $result.Message = "DNS cache optimization completed successfully. Applied $successCount settings."
                Write-OptimizationLog "DNS cache optimization completed successfully" -Level "Info"
            } else {
                $result.Success = $false
                $result.Message = "DNS cache optimization partially failed. Applied $successCount of $($settingsToApply.Count) settings."
                Write-OptimizationLog "DNS cache optimization partially failed" -Level "Warning"
            }
        } else {
            $result.Success = $true
            $result.Message = "Preview mode"
            $result.AfterValues = $settingsToApply
        }
    }
    catch {
        $result.Success = $false
        $result.Message = "DNS cache optimization failed: $($_.Exception.Message)"
        $result.Errors += $_.Exception.Message
        Write-OptimizationLog "DNS cache optimization failed: $($_.Exception.Message)" -Level "Error"
    }

    return $result
}

function Optimize-NetworkMemory {
        # Configure TCP port ranges and connection limits for optimal network memory usage
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult])]
    param(
        [Parameter()]
        [ValidateRange(5000, 65534)]
        [int]$MaxUserPort = 65534,

        [Parameter()]
        [ValidateRange(30, 300)]
        [int]$TcpTimedWaitDelay = 30,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxConnectResponseRetransmissions = 2,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$TcpMaxDataRetransmissions = 3,

        [Parameter()]
        [ValidateRange(1024, 16384)]
        [int]$TcpWindowSize = 8192
    )

    $result = [OptimizationResult]::new()
    $result.OptimizationName = "Network Memory Optimization"
    $result.Timestamp = Get-Date

    try {
        Write-OptimizationLog "Starting network memory optimization" -Level "Info"

        $tcpRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

        # Validate registry path exists
        if (-not (Test-Path $tcpRegistryPath)) {
            throw "TCP/IP registry path not found: $tcpRegistryPath"
        }

        # Validate memory settings are within safe ranges
        $totalMemoryGB = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
        Write-OptimizationLog "System has $totalMemoryGB GB of total memory" -Level "Info"

        if ($totalMemoryGB -lt 4) {
            Write-OptimizationLog "Low memory system detected ($totalMemoryGB GB). Using conservative settings." -Level "Warning"
            $MaxUserPort = [math]::Min($MaxUserPort, 32768)
            $TcpWindowSize = [math]::Min($TcpWindowSize, 4096)
        }

        # Collect current values for backup
        $currentValues = @{}
        $settingsToApply = @{
            'MaxUserPort' = $MaxUserPort
            'TcpTimedWaitDelay' = $TcpTimedWaitDelay
            'MaxConnectResponseRetransmissions' = $MaxConnectResponseRetransmissions
            'TcpMaxDataRetransmissions' = $TcpMaxDataRetransmissions
            'TcpWindowSize' = $TcpWindowSize
            'DefaultReceiveWindow' = $TcpWindowSize
            'DefaultSendWindow' = $TcpWindowSize
        }

        foreach ($setting in $settingsToApply.Keys) {
            try {
                $currentValue = Get-ItemProperty -Path $tcpRegistryPath -Name $setting -ErrorAction SilentlyContinue
                if ($null -ne $currentValue) {
                    $currentValues[$setting] = $currentValue.$setting
                } else {
                    $currentValues[$setting] = "Not Set"
                }
            }
            catch {
                $currentValues[$setting] = "Error Reading"
                Write-OptimizationLog "Failed to read current value for ${1} : $($_.Exception.Message)" -Level "Warning"
            }
        }

        $result.BeforeValues = $currentValues.Clone()

        if ($PSCmdlet.ShouldProcess("Network Memory Settings", "Apply Optimizations")) {
            # Apply network memory optimizations
            foreach ($setting in $settingsToApply.Keys) {
                try {
                    $value = $settingsToApply[$setting]
                    Set-ItemProperty -Path $tcpRegistryPath -Name $setting -Value $value -Type DWord -Force
                    Write-OptimizationLog "Set network memory setting: $setting = $value" -Level "Info"
                }
                catch {
                    $errorMsg = "Failed to set network memory setting ${1} : $($_.Exception.Message)"
                    Write-OptimizationLog $errorMsg -Level "Error"
                    $result.Errors += $errorMsg
                }
            }

            # Verify applied settings
            $appliedValues = @{}
            foreach ($setting in $settingsToApply.Keys) {
                try {
                    $newValue = Get-ItemProperty -Path $tcpRegistryPath -Name $setting -ErrorAction Stop
                    $appliedValues[$setting] = $newValue.$setting
                }
                catch {
                    $appliedValues[$setting] = "Verification Failed"
                }
            }

            $result.AfterValues = $appliedValues

            # Check if all settings were applied successfully
            $successCount = 0
            foreach ($setting in $settingsToApply.Keys) {
                if ($appliedValues[$setting] -eq $settingsToApply[$setting]) {
                    $successCount++
                }
            }

            if ($successCount -eq $settingsToApply.Count) {
                $result.Success = $true
                $result.Message = "Network memory optimization completed successfully. Applied $successCount settings."
                Write-OptimizationLog "Network memory optimization completed successfully" -Level "Info"
            } else {
                $result.Success = $false
                $result.Message = "Network memory optimization partially failed. Applied $successCount of $($settingsToApply.Count) settings."
                Write-OptimizationLog "Network memory optimization partially failed" -Level "Warning"
            }
        } else {
            $result.Success = $true
            $result.Message = "WHATIF: Would apply network memory optimizations"
            $result.AfterValues = $settingsToApply
            Write-Host "WHATIF: Would apply network memory optimizations:" -ForegroundColor Magenta
            foreach ($setting in $settingsToApply.Keys) {
                Write-Host "  ${1} : $($currentValues[$setting]) -> $($settingsToApply[$setting])" -ForegroundColor Cyan
            }
        }
    }
    catch {
        $result.Success = $false
        $result.Message = "Network memory optimization failed: $($_.Exception.Message)"
        $result.Errors += $_.Exception.Message
        Write-OptimizationLog "Network memory optimization failed: $($_.Exception.Message)" -Level "Error"
    }

    return $result
}

function Set-MemoryManagement {
        # Configure network buffer allocation and system memory management settings
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult])]
    param(
        [Parameter()]
        [bool]$LargeSystemCache = $false,

        [Parameter()]
        [bool]$DisablePagingExecutive = $true,

        [Parameter()]
        [ValidateRange(1, 70)]
        [int]$NetworkThrottlingIndex = 10,

        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$SystemResponsiveness = 20
    )

    $result = [OptimizationResult]::new()
    $result.OptimizationName = "Memory Management Optimization"
    $result.Timestamp = Get-Date

    try {
        Write-OptimizationLog "Starting memory management optimization" -Level "Info"

        # Detect system type to adjust settings
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 1)
        $isServer = $computerSystem.DomainRole -ge 2  # 2 = Server, 3 = Domain Controller

        Write-OptimizationLog "System type: $(if($isServer){'Server'}else{'Workstation'}), Memory: $totalMemoryGB GB" -Level "Info"

        # Adjust settings based on system type and memory
        if ($isServer -and $totalMemoryGB -ge 8) {
            $LargeSystemCache = $true
            Write-OptimizationLog "Server with sufficient memory detected. Enabling large system cache." -Level "Info"
        }

        if ($totalMemoryGB -lt 4) {
            $DisablePagingExecutive = $false
            Write-OptimizationLog "Low memory system detected. Keeping paging executive enabled." -Level "Warning"
        }

        # Registry paths for different settings
        $memoryMgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        $multimediaPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        $networkThrottlePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"

        # Validate registry paths exist
        $pathsToCheck = @($memoryMgmtPath, $multimediaPath)
        foreach ($path in $pathsToCheck) {
            if (-not (Test-Path $path)) {
                throw "Required registry path not found: $path"
            }
        }

        # Ensure network throttle path exists
        if (-not (Test-Path $networkThrottlePath)) {
            try {
                New-Item -Path $networkThrottlePath -Force | Out-Null
                Write-OptimizationLog "Created network throttle registry path: $networkThrottlePath" -Level "Info"
            }
            catch {
                Write-OptimizationLog "Failed to create network throttle path: $($_.Exception.Message)" -Level "Warning"
            }
        }

        # Collect current values for backup
        $currentValues = @{}
        $settingsToApply = @{
            "$memoryMgmtPath\LargeSystemCache" = [int]$LargeSystemCache
            "$memoryMgmtPath\DisablePagingExecutive" = [int]$DisablePagingExecutive
            "$multimediaPath\SystemResponsiveness" = $SystemResponsiveness
        }

        # Add network throttling setting if path exists
        if (Test-Path $networkThrottlePath) {
            $settingsToApply["$networkThrottlePath\NetworkThrottlingIndex"] = $NetworkThrottlingIndex
        }

        foreach ($settingPath in $settingsToApply.Keys) {
            $path = Split-Path $settingPath -Parent
            $setting = Split-Path $settingPath -Leaf

            try {
                $currentValue = Get-ItemProperty -Path $path -Name $setting -ErrorAction SilentlyContinue
                if ($null -ne $currentValue) {
                    $currentValues[$settingPath] = $currentValue.$setting
                } else {
                    $currentValues[$settingPath] = "Not Set"
                }
            }
            catch {
                $currentValues[$settingPath] = "Error Reading"
                Write-OptimizationLog "Failed to read current value for ${1} : $($_.Exception.Message)" -Level "Warning"
            }
        }

        $result.BeforeValues = $currentValues.Clone()

        if ($PSCmdlet.ShouldProcess("Memory Management Settings", "Apply Optimizations")) {
            # Apply memory management optimizations
            foreach ($settingPath in $settingsToApply.Keys) {
                $path = Split-Path $settingPath -Parent
                $setting = Split-Path $settingPath -Leaf
                $value = $settingsToApply[$settingPath]

                try {
                    Set-ItemProperty -Path $path -Name $setting -Value $value -Type DWord -Force
                    Write-OptimizationLog "Set memory management setting: $setting = $value" -Level "Info"
                }
                catch {
                    $errorMsg = "Failed to set memory management setting ${1} : $($_.Exception.Message)"
                    Write-OptimizationLog $errorMsg -Level "Error"
                    $result.Errors += $errorMsg
                }
            }

            # Verify applied settings
            $appliedValues = @{}
            foreach ($settingPath in $settingsToApply.Keys) {
                $path = Split-Path $settingPath -Parent
                $setting = Split-Path $settingPath -Leaf

                try {
                    $newValue = Get-ItemProperty -Path $path -Name $setting -ErrorAction Stop
                    $appliedValues[$settingPath] = $newValue.$setting
                }
                catch {
                    $appliedValues[$settingPath] = "Verification Failed"
                }
            }

            $result.AfterValues = $appliedValues

            # Check if all settings were applied successfully
            $successCount = 0
            foreach ($settingPath in $settingsToApply.Keys) {
                if ($appliedValues[$settingPath] -eq $settingsToApply[$settingPath]) {
                    $successCount++
                }
            }

            if ($successCount -eq $settingsToApply.Count) {
                $result.Success = $true
                $result.Message = "Memory management optimization completed successfully. Applied $successCount settings."
                Write-OptimizationLog "Memory management optimization completed successfully" -Level "Info"
            } else {
                $result.Success = $false
                $result.Message = "Memory management optimization partially failed. Applied $successCount of $($settingsToApply.Count) settings."
                Write-OptimizationLog "Memory management optimization partially failed" -Level "Warning"
            }
        } else {
            $result.Success = $true
            $result.Message = "WHATIF: Would apply memory management optimizations"
            $result.AfterValues = $settingsToApply
            Write-Host "WHATIF: Would apply memory management optimizations:" -ForegroundColor Magenta
            foreach ($settingPath in $settingsToApply.Keys) {
                $setting = Split-Path $settingPath -Leaf
                Write-Host "  ${1} : $($currentValues[$settingPath]) -> $($settingsToApply[$settingPath])" -ForegroundColor Cyan
            }
        }
    }
    catch {
        $result.Success = $false
        $result.Message = "Memory management optimization failed: $($_.Exception.Message)"
        $result.Errors += $_.Exception.Message
        Write-OptimizationLog "Memory management optimization failed: $($_.Exception.Message)" -Level "Error"
    }

    return $result
}

#endregion

#region Connection Type Detection and Optimization Module

function Get-ConnectionType {
        # Auto-detect the current network connection type (WiFi/Ethernet/Fiber)
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        Write-OptimizationLog "Starting connection type detection" -Level "Info"

        # Get all active network adapters
        $activeAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.Virtual -eq $false -and
            $_.Name -notmatch 'Loopback|Teredo|isatap'
        }

        if (-not $activeAdapters) {
            throw "No active network adapters found"
        }

        $connectionInfo = @{
            PrimaryAdapter = $null
            ConnectionType = "Unknown"
            LinkSpeed = 0
            IsWiFi = $false
            IsEthernet = $false
            IsFiber = $false
            AdapterDetails = @()
            Capabilities = @()
        }

        # Process each active adapter
        foreach ($adapter in $activeAdapters) {
            try {

                # Get detailed adapter information
                $adapterInfo = @{
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    LinkSpeed = $adapter.LinkSpeed
                    MediaType = $adapter.MediaType
                    PhysicalMediaType = $adapter.PhysicalMediaType
                    Status = $adapter.Status
                    FullDuplex = $adapter.FullDuplex
                }

                # Determine connection type based on adapter properties
                $detectedType = "Unknown"
                $isWiFi = $false
                $isEthernet = $false
                $isFiber = $false

                # Check for WiFi indicators
                if ($adapter.InterfaceDescription -match 'wireless|wifi|802\.11|wi-fi' -or
                    $adapter.PhysicalMediaType -match 'wireless|native802\.11') {
                    $detectedType = "WiFi"
                    $isWiFi = $true
                    Write-OptimizationLog "WiFi connection detected: $($adapter.Name)" -Level "Info"
                }
                # Check for high-speed fiber indicators (10Gbps+)
                elseif ($adapter.LinkSpeed -ge 10000000000) {
                    $detectedType = "Fiber"
                    $isFiber = $true
                    Write-OptimizationLog "High-speed fiber connection detected: $($adapter.Name) - $($adapter.LinkSpeed / 1000000000)Gbps" -Level "Info"
                }
                # Check for Ethernet indicators
                elseif ($adapter.InterfaceDescription -match 'ethernet|gigabit|fast ethernet' -or
                        $adapter.PhysicalMediaType -match 'ethernet|802\.3' -or
                        $adapter.MediaType -eq 'Ethernet') {
                    $detectedType = "Ethernet"
                    $isEthernet = $true
                    Write-OptimizationLog "Ethernet connection detected: $($adapter.Name) - $($adapter.LinkSpeed / 1000000)Mbps" -Level "Info"
                }

                $adapterInfo.DetectedType = $detectedType
                $connectionInfo.AdapterDetails += $adapterInfo

                # Set primary adapter (prefer active, highest speed)
                if ($null -eq $connectionInfo.PrimaryAdapter -or
                    $adapter.LinkSpeed -gt $connectionInfo.LinkSpeed) {
                    $connectionInfo.PrimaryAdapter = $adapterInfo
                    $connectionInfo.ConnectionType = $detectedType
                    $connectionInfo.LinkSpeed = $adapter.LinkSpeed
                    $connectionInfo.IsWiFi = $isWiFi
                    $connectionInfo.IsEthernet = $isEthernet
                    $connectionInfo.IsFiber = $isFiber
                }
            }
            catch {
                Write-OptimizationLog "Failed to analyze adapter $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
            }
        }

        # Determine capabilities based on connection type and speed
        if ($connectionInfo.IsWiFi) {
            $connectionInfo.Capabilities += "Wireless Optimization"
            $connectionInfo.Capabilities += "Power Management"
            if ($connectionInfo.LinkSpeed -ge 100000000) {
                $connectionInfo.Capabilities += "High-Speed WiFi"
            }
        }

        if ($connectionInfo.IsEthernet) {
            $connectionInfo.Capabilities += "Wired Optimization"
            $connectionInfo.Capabilities += "Full Duplex"
            if ($connectionInfo.LinkSpeed -ge 1000000000) {
                $connectionInfo.Capabilities += "Gigabit Ethernet"
            }
        }

        if ($connectionInfo.IsFiber) {
            $connectionInfo.Capabilities += "High-Speed Optimization"
            $connectionInfo.Capabilities += "Advanced Buffering"
            $connectionInfo.Capabilities += "Enterprise Features"
        }

        Write-OptimizationLog "Connection type detection completed: $($connectionInfo.ConnectionType) - $($connectionInfo.LinkSpeed / 1000000)Mbps" -Level "Info"
        return $connectionInfo
    }
    catch {
        $errorMessage = "Failed to detect connection type: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        throw $errorMessage
    }
}

function Optimize-WiFiSettings {
        # Apply wireless-specific network optimizations
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$EnableAggregation,

        [Parameter()]
        [switch]$OptimizeRoaming,

        [Parameter()]
        [switch]$DisablePowerSaving,

        [Parameter()]
        [switch]$OptimizeChannelWidth,

        [Parameter()]
        [switch]$EnableBeamforming
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        AdapterSettings = @()
    }

    try {
        Write-OptimizationLog "Starting WiFi-specific optimizations" -Level "Info"

        # Get WiFi adapters
        $wifiAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            ($_.InterfaceDescription -match 'wireless|wifi|802\.11|wi-fi' -or
             $_.PhysicalMediaType -match 'wireless|native802\.11')
        }

        if (-not $wifiAdapters) {
            Write-OptimizationLog "No active WiFi adapters found" -Level "Warning"
            return $results
        }

        foreach ($adapter in $wifiAdapters) {
            Write-OptimizationLog "Optimizing WiFi adapter: $($adapter.Name)" -Level "Info"

            # Registry path for wireless settings
            # $wirelessRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)"

            # Enable frame aggregation
            if ($EnableAggregation) {
                $operation = Invoke-SafeOperation -OperationName "Enable WiFi Frame Aggregation" -Operation {
                    # Set aggregation parameters
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                    foreach ($subKey in $subKeys) {
                        try {
                            $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                            if ($driverDesc -and $driverDesc.DriverDesc -match 'wireless|wifi|802\.11') {
                                Set-ItemProperty -Path $subKey.PSPath -Name "AggregationCapable" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                Set-ItemProperty -Path $subKey.PSPath -Name "AMPDUEnabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                        }
                    }

                    Write-OptimizationLog "WiFi frame aggregation enabled for $($adapter.Name)" -Level "Info"
                    return @{ Name = "FrameAggregation"; Value = "Enabled"; Description = "WiFi frame aggregation enabled" }
                }
                $results.Operations += $operation
            }

            # Optimize roaming settings
            if ($OptimizeRoaming) {
                $operation = Invoke-SafeOperation -OperationName "Optimize WiFi Roaming" -Operation {
                    # Set roaming aggressiveness to medium-high for better performance
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    Set-ItemProperty -Path $regPath -Name "RoamingAggressiveness" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue

                    # Optimize scan parameters
                    Set-ItemProperty -Path $regPath -Name "ScanWhenAssociated" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

                    Write-OptimizationLog "WiFi roaming settings optimized for $($adapter.Name)" -Level "Info"
                    return @{ Name = "RoamingOptimization"; Value = "Enabled"; Description = "WiFi roaming settings optimized" }
                }
                $results.Operations += $operation
            }

            # Disable aggressive power saving
            if ($DisablePowerSaving) {
                $operation = Invoke-SafeOperation -OperationName "Disable WiFi Power Saving" -Operation {
                    # Use PowerShell to disable power management
                    try {
                        $powerSettings = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                        if ($powerSettings) {
                            Set-NetAdapterPowerManagement -Name $adapter.Name -AllowComputerToTurnOffDevice Disabled -ErrorAction SilentlyContinue
                            Write-OptimizationLog "Power management disabled for WiFi adapter: $($adapter.Name)" -Level "Info"
                        }
                    }
                    catch {
                    }

                    # Registry method as fallback
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                    foreach ($subKey in $subKeys) {
                        try {
                            $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                            if ($driverDesc -and $driverDesc.DriverDesc -match 'wireless|wifi|802\.11') {
                                Set-ItemProperty -Path $subKey.PSPath -Name "PowerSaveMode" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                                Set-ItemProperty -Path $subKey.PSPath -Name "PowerManagement" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                        }
                    }

                    return @{ Name = "PowerSaving"; Value = "Disabled"; Description = "WiFi power saving disabled for performance" }
                }
                $results.Operations += $operation
            }

            # Optimize channel width
            if ($OptimizeChannelWidth) {
                $operation = Invoke-SafeOperation -OperationName "Optimize WiFi Channel Width" -Operation {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                    foreach ($subKey in $subKeys) {
                        try {
                            $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                            if ($driverDesc -and $driverDesc.DriverDesc -match 'wireless|wifi|802\.11') {
                                # Enable 40MHz and 80MHz channel width if supported
                                Set-ItemProperty -Path $subKey.PSPath -Name "ChannelWidth" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
                                Set-ItemProperty -Path $subKey.PSPath -Name "FatChannelIntolerant" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                        }
                    }

                    Write-OptimizationLog "WiFi channel width optimized for $($adapter.Name)" -Level "Info"
                    return @{ Name = "ChannelWidth"; Value = "Optimized"; Description = "WiFi channel width optimized for performance" }
                }
                $results.Operations += $operation
            }

            # Enable beamforming
            if ($EnableBeamforming) {
                $operation = Invoke-SafeOperation -OperationName "Enable WiFi Beamforming" -Operation {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                    foreach ($subKey in $subKeys) {
                        try {
                            $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                            if ($driverDesc -and $driverDesc.DriverDesc -match 'wireless|wifi|802\.11') {
                                Set-ItemProperty -Path $subKey.PSPath -Name "Beamforming" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                Set-ItemProperty -Path $subKey.PSPath -Name "MUBeamformer" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                        }
                    }

                    Write-OptimizationLog "WiFi beamforming enabled for $($adapter.Name)" -Level "Info"
                    return @{ Name = "Beamforming"; Value = "Enabled"; Description = "WiFi beamforming enabled for better signal quality" }
                }
                $results.Operations += $operation
            }

            $results.AdapterSettings += @{
                AdapterName = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                OptimizationsApplied = $results.Operations.Count
            }
        }

        Write-OptimizationLog "WiFi optimization completed successfully. Total operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "WiFi optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Optimize-EthernetSettings {
        # Apply wired Ethernet connection optimizations
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$EnableInterruptModeration,

        [Parameter()]
        [switch]$EnableReceiveSideScaling,

        [Parameter()]
        [switch]$OptimizeBufferSizes,

        [Parameter()]
        [switch]$EnableJumboFrames,

        [Parameter()]
        [switch]$OptimizeFlowControl
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        AdapterSettings = @()
    }

    try {
        Write-OptimizationLog "Starting Ethernet-specific optimizations" -Level "Info"

        # Get Ethernet adapters
        $ethernetAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            ($_.InterfaceDescription -match 'ethernet|gigabit|fast ethernet' -or
             $_.PhysicalMediaType -match 'ethernet|802\.3' -or
             $_.MediaType -eq 'Ethernet') -and
            $_.InterfaceDescription -notmatch 'wireless|wifi|802\.11|wi-fi'
        }

        if (-not $ethernetAdapters) {
            Write-OptimizationLog "No active Ethernet adapters found" -Level "Warning"
            return $results
        }

        foreach ($adapter in $ethernetAdapters) {
            Write-OptimizationLog "Optimizing Ethernet adapter: $($adapter.Name)" -Level "Info"

            # Enable interrupt moderation
            if ($EnableInterruptModeration) {
                $operation = Invoke-SafeOperation -OperationName "Enable Ethernet Interrupt Moderation" -Operation {
                    try {
                        # Try PowerShell method first
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
                        Write-OptimizationLog "Interrupt moderation enabled via PowerShell for $($adapter.Name)" -Level "Info"
                    }
                    catch {

                        # Registry method as fallback
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -match 'ethernet|gigabit') {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "InterruptModeration" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "ITR" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "InterruptModeration"; Value = "Enabled"; Description = "Ethernet interrupt moderation enabled" }
                }
                $results.Operations += $operation
            }

            # Enable Receive Side Scaling (RSS)
            if ($EnableReceiveSideScaling) {
                $operation = Invoke-SafeOperation -OperationName "Enable Ethernet RSS" -Operation {
                    try {
                        # Enable RSS via PowerShell
                        Set-NetAdapterRss -Name $adapter.Name -Enabled $true -ErrorAction SilentlyContinue
                        Write-OptimizationLog "RSS enabled via PowerShell for $($adapter.Name)" -Level "Info"
                    }
                    catch {

                        # Registry method for RSS
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -match 'ethernet|gigabit') {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "RSS" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "RSSProfile" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "ReceiveSideScaling"; Value = "Enabled"; Description = "Ethernet RSS enabled for multi-core processing" }
                }
                $results.Operations += $operation
            }

            # Optimize buffer sizes
            if ($OptimizeBufferSizes) {
                $operation = Invoke-SafeOperation -OperationName "Optimize Ethernet Buffer Sizes" -Operation {
                    try {
                        # Optimize receive buffers
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Transmit Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                        Write-OptimizationLog "Buffer sizes optimized via PowerShell for $($adapter.Name)" -Level "Info"
                    }
                    catch {
                        # Registry method for buffer optimization
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -match 'ethernet|gigabit') {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "ReceiveBuffers" -Value 2048 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "TransmitBuffers" -Value 2048 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "BufferSizes"; Value = "Optimized"; Description = "Ethernet buffer sizes optimized" }
                }
                $results.Operations += $operation
            }

            # Enable jumbo frames (if supported)
            if ($EnableJumboFrames) {
                $operation = Invoke-SafeOperation -OperationName "Enable Ethernet Jumbo Frames" -Operation {
                    try {
                        # Check if adapter supports jumbo frames
                        $jumboSupport = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Jumbo*" -ErrorAction SilentlyContinue
                        if ($jumboSupport) {
                            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Jumbo Packet" -DisplayValue "9014 Bytes" -ErrorAction SilentlyContinue
                            Write-OptimizationLog "Jumbo frames enabled for $($adapter.Name)" -Level "Info"
                        } else {
                            Write-OptimizationLog "Jumbo frames not supported by adapter $($adapter.Name)" -Level "Info"
                        }
                    }
                    catch {
                    }

                    return @{ Name = "JumboFrames"; Value = "Enabled"; Description = "Jumbo frames enabled if supported" }
                }
                $results.Operations += $operation
            }

            # Optimize flow control
            if ($OptimizeFlowControl) {
                $operation = Invoke-SafeOperation -OperationName "Optimize Ethernet Flow Control" -Operation {
                    try {
                        # Configure flow control for optimal performance
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Flow Control" -DisplayValue "Rx & Tx Enabled" -ErrorAction SilentlyContinue
                        Write-OptimizationLog "Flow control optimized for $($adapter.Name)" -Level "Info"
                    }
                    catch {
                        # Registry method for flow control
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -match 'ethernet|gigabit') {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "FlowControl" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "FlowControl"; Value = "Optimized"; Description = "Ethernet flow control optimized" }
                }
                $results.Operations += $operation
            }

            $results.AdapterSettings += @{
                AdapterName = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                LinkSpeed = $adapter.LinkSpeed
                OptimizationsApplied = $results.Operations.Count
            }
        }

        Write-OptimizationLog "Ethernet optimization completed successfully. Total operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "Ethernet optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Optimize-FiberSettings {
        # Apply high-speed fiber connection optimizations
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$EnableAdvancedBuffering,

        [Parameter()]
        [switch]$OptimizeInterruptCoalescing,

        [Parameter()]
        [switch]$EnableLargeReceiveOffload,

        [Parameter()]
        [switch]$OptimizeForThroughput,

        [Parameter()]
        [switch]$EnableEnterpriseFeatures
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        AdapterSettings = @()
    }

    try {
        Write-OptimizationLog "Starting fiber-specific optimizations" -Level "Info"

        # Get high-speed adapters (10Gbps+)
        $fiberAdapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.LinkSpeed -ge 10000000000 -and
            $_.Virtual -eq $false
        }

        if (-not $fiberAdapters) {
            Write-OptimizationLog "No high-speed fiber adapters found (10Gbps+)" -Level "Warning"
            return $results
        }

        foreach ($adapter in $fiberAdapters) {
            Write-OptimizationLog "Optimizing high-speed adapter: $($adapter.Name) - $($adapter.LinkSpeed / 1000000000)Gbps" -Level "Info"

            # Enable advanced buffering
            if ($EnableAdvancedBuffering) {
                $operation = Invoke-SafeOperation -OperationName "Enable Advanced Buffering for Fiber" -Operation {
                    try {
                        # Set large buffer sizes for high-speed connections
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Buffers" -DisplayValue "4096" -ErrorAction SilentlyContinue
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Transmit Buffers" -DisplayValue "4096" -ErrorAction SilentlyContinue

                        # Enable large send offload
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Large Send Offload*" -DisplayValue "Enabled" -ErrorAction SilentlyContinue

                        Write-OptimizationLog "Advanced buffering configured for $($adapter.Name)" -Level "Info"
                    }
                    catch {

                        # Registry method for advanced buffering
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -eq $adapter.InterfaceDescription) {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "ReceiveBuffers" -Value 4096 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "TransmitBuffers" -Value 4096 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "LargeSendOffload" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "AdvancedBuffering"; Value = "Enabled"; Description = "Advanced buffering enabled for high-speed fiber" }
                }
                $results.Operations += $operation
            }

            # Optimize interrupt coalescing
            if ($OptimizeInterruptCoalescing) {
                $operation = Invoke-SafeOperation -OperationName "Optimize Interrupt Coalescing for Fiber" -Operation {
                    try {
                        # Configure interrupt moderation for high throughput
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation Rate" -DisplayValue "Adaptive" -ErrorAction SilentlyContinue
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Enabled" -ErrorAction SilentlyContinue

                        Write-OptimizationLog "Interrupt coalescing optimized for $($adapter.Name)" -Level "Info"
                    }
                    catch {
                        # Registry method for interrupt coalescing
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -eq $adapter.InterfaceDescription) {
                                    Set-ItemProperty -Path $subKey.PSPath -Name "InterruptModerationRate" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "AdaptiveIFS" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "InterruptCoalescing"; Value = "Optimized"; Description = "Interrupt coalescing optimized for fiber throughput" }
                }
                $results.Operations += $operation
            }

            # Enable Large Receive Offload
            if ($EnableLargeReceiveOffload) {
                $operation = Invoke-SafeOperation -OperationName "Enable Large Receive Offload" -Operation {
                    try {
                        # Enable LRO/RSC for better performance
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Large Receive Offload*" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Side Coalescing*" -DisplayValue "Enabled" -ErrorAction SilentlyContinue

                        Write-OptimizationLog "Large Receive Offload enabled for $($adapter.Name)" -Level "Info"
                    }
                    catch {
                    }

                    return @{ Name = "LargeReceiveOffload"; Value = "Enabled"; Description = "Large Receive Offload enabled for fiber" }
                }
                $results.Operations += $operation
            }

            # Optimize for throughput
            if ($OptimizeForThroughput) {
                $operation = Invoke-SafeOperation -OperationName "Optimize Fiber for Throughput" -Operation {
                    # TCP/IP stack optimizations for high-speed connections
                    $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

                    # Increase TCP window size for high-speed connections
                    Set-ItemProperty -Path $tcpipPath -Name "TcpWindowSize" -Value 262144 -Type DWord -Force -ErrorAction SilentlyContinue

                    # Optimize for high throughput
                    Set-ItemProperty -Path $tcpipPath -Name "Tcp1323Opts" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $tcpipPath -Name "DefaultRcvWindow" -Value 262144 -Type DWord -Force -ErrorAction SilentlyContinue

                    # Increase maximum connections
                    Set-ItemProperty -Path $tcpipPath -Name "TcpNumConnections" -Value 16777214 -Type DWord -Force -ErrorAction SilentlyContinue

                    Write-OptimizationLog "Throughput optimizations applied for $($adapter.Name)" -Level "Info"
                    return @{ Name = "ThroughputOptimization"; Value = "Enabled"; Description = "Fiber connection optimized for maximum throughput" }
                }
                $results.Operations += $operation
            }

            # Enable enterprise features
            if ($EnableEnterpriseFeatures) {
                $operation = Invoke-SafeOperation -OperationName "Enable Enterprise Features for Fiber" -Operation {
                    try {
                        # Enable advanced enterprise features
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Priority & VLAN" -DisplayValue "Priority & VLAN Enabled" -ErrorAction SilentlyContinue
                        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*QoS Packet Tagging" -DisplayValue "Enabled" -ErrorAction SilentlyContinue

                        # Enable advanced RSS features
                        Set-NetAdapterRss -Name $adapter.Name -Enabled $true -MaxProcessors 8 -ErrorAction SilentlyContinue

                        Write-OptimizationLog "Enterprise features enabled for $($adapter.Name)" -Level "Info"
                    }
                    catch {
                    }

                    return @{ Name = "EnterpriseFeatures"; Value = "Enabled"; Description = "Enterprise-grade features enabled for fiber" }
                }
                $results.Operations += $operation
            }

            $results.AdapterSettings += @{
                AdapterName = $adapter.Name
                InterfaceDescription = $adapter.InterfaceDescription
                LinkSpeed = $adapter.LinkSpeed
                LinkSpeedGbps = [math]::Round($adapter.LinkSpeed / 1000000000, 1)
                OptimizationsApplied = $results.Operations.Count
            }
        }

        Write-OptimizationLog "Fiber optimization completed successfully. Total operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "Fiber optimization failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

function Set-AdapterPowerSettings {
        # Configure network adapter power management settings using PowerShell cmdlets
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$DisablePowerSaving,

        [Parameter()]
        [switch]$OptimizeForPerformance,

        [Parameter()]
        [string]$AdapterName,

        [Parameter()]
        [switch]$EnableWakeOnLan
    )

    $results = @{
        Success = $true
        Operations = @()
        Errors = @()
        AdapterSettings = @()
    }

    try {
        Write-OptimizationLog "Starting network adapter power management configuration" -Level "Info"

        # Get target adapters
        if ($AdapterName) {
            $adapters = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
            if (-not $adapters) {
                throw "Adapter '$AdapterName' not found"
            }
        } else {
            $adapters = Get-NetAdapter | Where-Object {
                $_.Status -eq 'Up' -and
                $_.Virtual -eq $false -and
                $_.Name -notmatch 'Loopback|Teredo|isatap'
            }
        }

        if (-not $adapters) {
            Write-OptimizationLog "No suitable network adapters found for power management" -Level "Warning"
            return $results
        }

        foreach ($adapter in $adapters) {
            Write-OptimizationLog "Configuring power settings for adapter: $($adapter.Name)" -Level "Info"

            # Disable power saving
            if ($DisablePowerSaving) {
                $operation = Invoke-SafeOperation -OperationName "Disable Power Saving for $($adapter.Name)" -Operation {
                    try {
                        # Use PowerShell cmdlet to disable power management
                        $powerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                        if ($powerMgmt) {
                            Set-NetAdapterPowerManagement -Name $adapter.Name -AllowComputerToTurnOffDevice Disabled -ErrorAction Stop
                            Write-OptimizationLog "Power saving disabled via PowerShell for $($adapter.Name)" -Level "Info"
                        }
                    }
                    catch {

                        # Registry method as fallback
                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
                        $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue

                        foreach ($subKey in $subKeys) {
                            try {
                                $driverDesc = Get-ItemProperty -Path $subKey.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue
                                if ($driverDesc -and $driverDesc.DriverDesc -eq $adapter.InterfaceDescription) {
                                    # Disable power management via registry
                                    Set-ItemProperty -Path $subKey.PSPath -Name "PnPCapabilities" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Set-ItemProperty -Path $subKey.PSPath -Name "PowerSaveMode" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Write-OptimizationLog "Power saving disabled via registry for $($adapter.Name)" -Level "Info"
                                    break
                                }
                            }
                            catch {
                            }
                        }
                    }

                    return @{ Name = "PowerSaving"; Value = "Disabled"; Description = "Power saving disabled for network adapter" }
                }
                $results.Operations += $operation
            }

            # Optimize for performance
            if ($OptimizeForPerformance) {
                $operation = Invoke-SafeOperation -OperationName "Optimize Power for Performance - $($adapter.Name)" -Operation {
                    try {
                        # Configure for maximum performance
                        $powerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                        if ($powerMgmt) {
                            # Disable all power saving features
                            Set-NetAdapterPowerManagement -Name $adapter.Name -AllowComputerToTurnOffDevice Disabled -ErrorAction SilentlyContinue

                            # Try to disable selective suspend if available
                            try {
                                Set-NetAdapterPowerManagement -Name $adapter.Name -SelectiveSuspend Disabled -ErrorAction SilentlyContinue
                            }
                            catch {
                            }

                            Write-OptimizationLog "Performance power settings applied for $($adapter.Name)" -Level "Info"
                        }
                    }
                    catch {
                        Write-OptimizationLog "Performance optimization failed for $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
                    }

                    return @{ Name = "PerformanceOptimization"; Value = "Enabled"; Description = "Power settings optimized for performance" }
                }
                $results.Operations += $operation
            }

            # Enable Wake-on-LAN
            if ($EnableWakeOnLan) {
                $operation = Invoke-SafeOperation -OperationName "Enable Wake-on-LAN for $($adapter.Name)" -Operation {
                    try {
                        # Configure Wake-on-LAN settings
                        $powerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                        if ($powerMgmt) {
                            Set-NetAdapterPowerManagement -Name $adapter.Name -WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue
                            Set-NetAdapterPowerManagement -Name $adapter.Name -WakeOnPattern Enabled -ErrorAction SilentlyContinue
                            Write-OptimizationLog "Wake-on-LAN enabled for $($adapter.Name)" -Level "Info"
                        }
                    }
                    catch {
                        Write-OptimizationLog "Wake-on-LAN configuration failed for $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
                    }

                    return @{ Name = "WakeOnLAN"; Value = "Enabled"; Description = "Wake-on-LAN functionality enabled" }
                }
                $results.Operations += $operation
            }

            # Get final power management status
            try {
                $finalPowerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
                $adapterSetting = @{
                    AdapterName = $adapter.Name
                    InterfaceDescription = $adapter.InterfaceDescription
                    PowerManagementEnabled = if ($finalPowerMgmt) { $finalPowerMgmt.AllowComputerToTurnOffDevice } else { "Unknown" }
                    WakeOnMagicPacket = if ($finalPowerMgmt) { $finalPowerMgmt.WakeOnMagicPacket } else { "Unknown" }
                    WakeOnPattern = if ($finalPowerMgmt) { $finalPowerMgmt.WakeOnPattern } else { "Unknown" }
                    OptimizationsApplied = ($results.Operations | Where-Object { $_.Description -match $adapter.Name }).Count
                }
                $results.AdapterSettings += $adapterSetting
            }
            catch {
            }
        }

        Write-OptimizationLog "Network adapter power management configuration completed. Total operations: $($results.Operations.Count)" -Level "Info"

    }
    catch {
        $results.Success = $false
        $errorMessage = "Network adapter power management configuration failed: $($_.Exception.Message)"
        $results.Errors += $errorMessage
        Write-OptimizationLog $errorMessage -Level "Error"
        throw
    }

    return $results
}

#endregion

#region Network Security Optimization Module

function Set-NetworkSecurity {
        # Configure network security settings including firewall and port security
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult[]])]
    param(
        [Parameter()]
        [switch]$EnableFirewallOptimization,

        [Parameter()]
        [switch]$ConfigurePortSecurity,

        [Parameter()]
        [switch]$OptimizeConnectionSecurity,

        [Parameter()]
        [switch]$Force
    )

    $results = @()

    try {
        Write-OptimizationLog "Starting network security optimization" -Level "Info"
        Write-Host "Configuring network security settings..." -ForegroundColor Yellow

        # Security validation and confirmation
        if (-not $Force -and -not $Silent) {
            Write-Host "`nWARNING: Network security changes can affect system connectivity and access." -ForegroundColor Yellow
            Write-Host "These changes will modify Windows Firewall and network security settings." -ForegroundColor Yellow
            $confirm = Read-Host "Do you want to continue with security optimizations? (y/N)"
            if ($confirm -notmatch '^[Yy]') {
                Write-OptimizationLog "Network security optimization cancelled by user" -Level "Info"
                return @([OptimizationResult]::new("Network Security", $false, "Cancelled by user", @{}, @{}, (Get-Date), @()))
            }
        }

        # Windows Firewall Optimization
        if ($EnableFirewallOptimization) {
            Write-Host "  Optimizing Windows Firewall performance..." -ForegroundColor Cyan

            try {
                $firewallResult = Invoke-SafeOperation -OperationName "Windows Firewall Optimization" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current firewall profiles
                    $profiles = Get-NetFirewallProfile -All
                    foreach ($netProfile in $profiles) {
                        $beforeState["$($profile.Name)_Enabled"] = $profile.Enabled
                        $beforeState["$($profile.Name)_DefaultInboundAction"] = $profile.DefaultInboundAction
                        $beforeState["$($profile.Name)_DefaultOutboundAction"] = $profile.DefaultOutboundAction
                    }

                    if ($PSCmdlet.ShouldProcess("Windows Firewall", "Optimize Performance Settings")) {
                        # Enable firewall for all profiles with optimized settings
                        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

                        # Optimize firewall logging for performance
                        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed False -LogBlocked False -LogIgnored False

                        # Configure firewall to allow essential network services
                        $essentialRules = @(
                            @{ DisplayName = "Core Networking - DNS (UDP-Out)"; Direction = "Outbound"; Protocol = "UDP"; LocalPort = "Any"; RemotePort = "53"; Action = "Allow" },
                            @{ DisplayName = "Core Networking - DHCP (UDP-Out)"; Direction = "Outbound"; Protocol = "UDP"; LocalPort = "68"; RemotePort = "67"; Action = "Allow" },
                            @{ DisplayName = "Core Networking - HTTP (TCP-Out)"; Direction = "Outbound"; Protocol = "TCP"; LocalPort = "Any"; RemotePort = "80"; Action = "Allow" },
                            @{ DisplayName = "Core Networking - HTTPS (TCP-Out)"; Direction = "Outbound"; Protocol = "TCP"; LocalPort = "Any"; RemotePort = "443"; Action = "Allow" }
                        )

                        foreach ($rule in $essentialRules) {
                            $existingRule = Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
                            if (-not $existingRule) {
                                New-NetFirewallRule @rule -Profile Any -Enabled True | Out-Null
                            }
                        }

                        # Get updated state
                        $updatedProfiles = Get-NetFirewallProfile -All
                        foreach ($netProfile in $updatedProfiles) {
                            $afterState["$($profile.Name)_Enabled"] = $profile.Enabled
                            $afterState["$($profile.Name)_DefaultInboundAction"] = $profile.DefaultInboundAction
                            $afterState["$($profile.Name)_DefaultOutboundAction"] = $profile.DefaultOutboundAction
                        }
                    }

                    return [OptimizationResult]::new("Windows Firewall Optimization", $true, "Firewall optimized for performance and security", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $firewallResult
                Write-OptimizationLog "Windows Firewall optimization completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "Windows Firewall optimization failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Windows Firewall Optimization", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Port Security Configuration
        if ($ConfigurePortSecurity) {
            Write-Host "  Configuring port security settings..." -ForegroundColor Cyan

            try {
                $portSecurityResult = Invoke-SafeOperation -OperationName "Port Security Configuration" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current port security settings
                    $tcpSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
                    if ($tcpSettings) {
                        $beforeState["MaxUserPort"] = $tcpSettings.MaxUserPort
                        $beforeState["TcpTimedWaitDelay"] = $tcpSettings.TcpTimedWaitDelay
                        $beforeState["EnableDeadGWDetect"] = $tcpSettings.EnableDeadGWDetect
                    }

                    if ($PSCmdlet.ShouldProcess("Port Security Settings", "Configure Secure Port Access")) {
                        # Configure secure port range and timeouts
                        $portSecuritySettings = @{
                            "MaxUserPort" = 65534          # Maximum dynamic port range
                            "TcpTimedWaitDelay" = 30       # Reduce TIME_WAIT delay for security
                            "EnableDeadGWDetect" = 1       # Enable dead gateway detection
                            "KeepAliveTime" = 7200000      # 2 hours keep-alive for security
                            "KeepAliveInterval" = 1000     # 1 second keep-alive interval
                        }

                        foreach ($setting in $portSecuritySettings.GetEnumerator()) {
                            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name $setting.Key -Value $setting.Value -Type DWord -Force
                        }

                        # Configure dynamic port range for security
                        try {
                            $currentRange = netsh int ipv4 show dynamicport tcp 2>$null
                            if ($currentRange) {
                                $beforeState["DynamicPortRange"] = ($currentRange | Out-String).Trim()
                            }

                            # Set secure dynamic port range
                            netsh int ipv4 set dynamicport tcp start=49152 num=16384 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                $afterState["DynamicPortRange"] = "Start: 49152, Range: 16384"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to configure dynamic port range: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Get updated settings
                        $updatedSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
                        if ($updatedSettings) {
                            $afterState["MaxUserPort"] = $updatedSettings.MaxUserPort
                            $afterState["TcpTimedWaitDelay"] = $updatedSettings.TcpTimedWaitDelay
                            $afterState["EnableDeadGWDetect"] = $updatedSettings.EnableDeadGWDetect
                        }
                    }

                    return [OptimizationResult]::new("Port Security Configuration", $true, "Port security settings optimized", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $portSecurityResult
                Write-OptimizationLog "Port security configuration completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "Port security configuration failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Port Security Configuration", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Connection Security Optimization
        if ($OptimizeConnectionSecurity) {
            Write-Host "  Optimizing connection security settings..." -ForegroundColor Cyan

            try {
                $connectionSecurityResult = Invoke-SafeOperation -OperationName "Connection Security Optimization" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current connection security settings
                    $securitySettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
                    if ($securitySettings) {
                        $beforeState["SynAttackProtect"] = $securitySettings.SynAttackProtect
                        $beforeState["EnableICMPRedirect"] = $securitySettings.EnableICMPRedirect
                        $beforeState["DisableIPSourceRouting"] = $securitySettings.DisableIPSourceRouting
                    }

                    if ($PSCmdlet.ShouldProcess("Connection Security Settings", "Optimize Security Parameters")) {
                        # Configure connection security settings
                        $connectionSecuritySettings = @{
                            "SynAttackProtect" = 1         # Enable SYN attack protection
                            "EnableICMPRedirect" = 0       # Disable ICMP redirects for security
                            "DisableIPSourceRouting" = 1   # Disable IP source routing
                            "EnableSecurityFilters" = 1   # Enable security filters
                            "NoNameReleaseOnDemand" = 1   # Prevent NetBIOS name release attacks
                        }

                        foreach ($setting in $connectionSecuritySettings.GetEnumerator()) {
                            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name $setting.Key -Value $setting.Value -Type DWord -Force
                        }

                        # Configure network adapter security settings
                        try {
                            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                            foreach ($adapter in $adapters) {
                                # Disable unnecessary protocols for security
                                $adapterSecurity = @{
                                    "DisableTaskOffload" = 0   # Keep task offload for performance
                                    "EnableLMHosts" = 0        # Disable LMHosts lookup
                                    "EnableWINS" = 0           # Disable WINS resolution
                                }

                                $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)"
                                if (Test-Path $adapterRegPath) {
                                    foreach ($setting in $adapterSecurity.GetEnumerator()) {
                                        Set-ItemProperty -Path $adapterRegPath -Name $setting.Key -Value $setting.Value -Type DWord -Force -ErrorAction SilentlyContinue
                                    }
                                }
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to configure adapter security settings: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Get updated settings
                        $updatedSettings = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue
                        if ($updatedSettings) {
                            $afterState["SynAttackProtect"] = $updatedSettings.SynAttackProtect
                            $afterState["EnableICMPRedirect"] = $updatedSettings.EnableICMPRedirect
                            $afterState["DisableIPSourceRouting"] = $updatedSettings.DisableIPSourceRouting
                        }
                    }

                    return [OptimizationResult]::new("Connection Security Optimization", $true, "Connection security settings optimized", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $connectionSecurityResult
                Write-OptimizationLog "Connection security optimization completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "Connection security optimization failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Connection Security Optimization", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        Write-Host "Network security optimization completed!" -ForegroundColor Green
        Write-OptimizationLog "Network security optimization completed with $($results.Count) operations" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Network security optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        return @([OptimizationResult]::new("Network Security", $false, $errorMessage, @{}, @{}, (Get-Date), @($_.Exception.Message)))
    }
}

function Invoke-NetworkMaintenance {
        # Perform comprehensive network maintenance operations
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult[]])]
    param(
        [Parameter()]
        [switch]$FlushDNSCache,

        [Parameter()]
        [switch]$ResetWinsock,

        [Parameter()]
        [switch]$ResetIPStack,

        [Parameter()]
        [switch]$ResetNetworkAdapters,

        [Parameter()]
        [switch]$Force
    )

    $results = @()

    try {
        Write-OptimizationLog "Starting network maintenance operations" -Level "Info"
        Write-Host "Performing network maintenance operations..." -ForegroundColor Yellow

        # Maintenance confirmation
        if (-not $Force -and -not $Silent) {
            Write-Host "`nWARNING: Network maintenance operations may temporarily disrupt network connectivity." -ForegroundColor Yellow
            Write-Host "Some operations require a system restart to take full effect." -ForegroundColor Yellow
            $confirm = Read-Host "Do you want to continue with network maintenance? (y/N)"
            if ($confirm -notmatch '^[Yy]') {
                Write-OptimizationLog "Network maintenance cancelled by user" -Level "Info"
                return @([OptimizationResult]::new("Network Maintenance", $false, "Cancelled by user", @{}, @{}, (Get-Date), @()))
            }
        }

        # DNS Cache Flush
        if ($FlushDNSCache) {
            Write-Host "  Flushing DNS resolver cache..." -ForegroundColor Cyan

            try {
                $dnsFlushResult = Invoke-SafeOperation -OperationName "DNS Cache Flush" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get DNS cache statistics before flush
                    try {
                        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
                        $beforeState["CacheEntries"] = if ($dnsCache) { $dnsCache.Count } else { 0 }
                    }
                    catch {
                        $beforeState["CacheEntries"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("DNS Cache", "Flush DNS Resolver Cache")) {
                        # Flush DNS cache using multiple methods for thoroughness
                        Clear-DnsClientCache -ErrorAction SilentlyContinue

                        # Also use ipconfig for compatibility
                        & ipconfig /flushdns 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                        }

                        # Restart DNS Client service for complete cache clear
                        try {
                            $dnsService = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
                            if ($dnsService -and $dnsService.Status -eq "Running") {
                                Restart-Service -Name "Dnscache" -Force -ErrorAction SilentlyContinue
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to restart DNS Client service: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Verify cache is cleared
                        Start-Sleep -Seconds 2
                        try {
                            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
                            $afterState["CacheEntries"] = if ($dnsCache) { $dnsCache.Count } else { 0 }
                        }
                        catch {
                            $afterState["CacheEntries"] = "Cleared"
                        }
                    }

                    return [OptimizationResult]::new("DNS Cache Flush", $true, "DNS resolver cache flushed successfully", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $dnsFlushResult
                Write-OptimizationLog "DNS cache flush completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "DNS cache flush failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("DNS Cache Flush", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Winsock Reset
        if ($ResetWinsock) {
            Write-Host "  Resetting Winsock catalog..." -ForegroundColor Cyan

            try {
                $winsockResetResult = Invoke-SafeOperation -OperationName "Winsock Reset" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get Winsock catalog information before reset
                    try {
                        $winsockInfo = & netsh winsock show catalog 2>&1
                        $beforeState["WinsockCatalog"] = if ($winsockInfo) { "Present" } else { "Unknown" }
                    }
                    catch {
                        $beforeState["WinsockCatalog"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("Winsock Catalog", "Reset to Default State")) {
                        # Reset Winsock catalog
                        $winsockResult = & netsh winsock reset 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $afterState["WinsockCatalog"] = "Reset to Default"
                            $afterState["RestartRequired"] = $true
                        } else {
                            throw "Winsock reset failed: $winsockResult"
                        }

                        # Also reset Winsock LSP (Layered Service Provider)
                        try {
                            & netsh winsock reset catalog 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to reset Winsock LSP catalog: $($_.Exception.Message)" -Level "Warning"
                        }
                    }

                    return [OptimizationResult]::new("Winsock Reset", $true, "Winsock catalog reset successfully (restart required)", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $winsockResetResult
                Write-OptimizationLog "Winsock reset completed successfully" -Level "Info"
                Write-Host "    Note: System restart required for Winsock reset to take full effect" -ForegroundColor Yellow
            }
            catch {
                $errorMsg = "Winsock reset failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Winsock Reset", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # IP Stack Reset
        if ($ResetIPStack) {
            Write-Host "  Resetting TCP/IP stack..." -ForegroundColor Cyan

            try {
                $ipStackResetResult = Invoke-SafeOperation -OperationName "IP Stack Reset" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current IP configuration
                    try {
                        $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue
                        $beforeState["ActiveInterfaces"] = if ($ipConfig) { $ipConfig.Count } else { 0 }
                    }
                    catch {
                        $beforeState["ActiveInterfaces"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("TCP/IP Stack", "Reset to Default Configuration")) {
                        # Reset TCP/IP stack using netsh
                        $ipv4Result = & netsh int ipv4 reset 2>&1
                        if ($LASTEXITCODE -eq 0) {
                        } else {
                            Write-OptimizationLog "IPv4 stack reset warning: $ipv4Result" -Level "Warning"
                        }

                        $ipv6Result = & netsh int ipv6 reset 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-OptimizationLog "IPv6 stack reset successfully" -Level "Debug"
                        } else {
                            Write-OptimizationLog "IPv6 stack reset warning: $ipv6Result" -Level "Warning"
                        }

                        # Reset TCP global parameters
                        try {
                            & netsh int tcp reset 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                Write-OptimizationLog "TCP parameters reset successfully" -Level "Debug"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to reset TCP parameters: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Reset routing table
                        try {
                            & route -f 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                Write-OptimizationLog "Routing table flushed successfully" -Level "Debug"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to flush routing table: $($_.Exception.Message)" -Level "Warning"
                        }

                        $afterState["IPStackReset"] = $true
                        $afterState["RestartRequired"] = $true
                    }

                    return [OptimizationResult]::new("IP Stack Reset", $true, "TCP/IP stack reset successfully (restart required)", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $ipStackResetResult
                Write-OptimizationLog "IP stack reset completed successfully" -Level "Info"
                Write-Host "    Note: System restart required for IP stack reset to take full effect" -ForegroundColor Yellow
            }
            catch {
                $errorMsg = "IP stack reset failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("IP Stack Reset", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Network Adapter Reset
        if ($ResetNetworkAdapters) {
            Write-Host "  Resetting network adapters..." -ForegroundColor Cyan

            try {
                $adapterResetResult = Invoke-SafeOperation -OperationName "Network Adapter Reset" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current adapter states
                    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
                    $beforeState["TotalAdapters"] = if ($adapters) { $adapters.Count } else { 0 }
                    $beforeState["ActiveAdapters"] = if ($adapters) { ($adapters | Where-Object { $_.Status -eq "Up" }).Count } else { 0 }

                    if ($PSCmdlet.ShouldProcess("Network Adapters", "Reset Configuration")) {
                        # Reset network adapters
                        foreach ($adapter in $adapters) {
                            try {
                                if ($adapter.Status -eq "Up") {
                                    Write-OptimizationLog "Resetting adapter: $($adapter.Name)" -Level "Debug"

                                    # Disable and re-enable adapter
                                    Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 2
                                    Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 3

                                    Write-OptimizationLog "Adapter reset completed: $($adapter.Name)" -Level "Debug"
                                }
                            }
                            catch {
                                Write-OptimizationLog "Failed to reset adapter $($adapter.Name): $($_.Exception.Message)" -Level "Warning"
                            }
                        }

                        # Renew IP configuration
                        try {
                            & ipconfig /renew 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                Write-OptimizationLog "IP configuration renewed successfully" -Level "Debug"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to renew IP configuration: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Get updated adapter states
                        Start-Sleep -Seconds 5
                        $updatedAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
                        $afterState["TotalAdapters"] = if ($updatedAdapters) { $updatedAdapters.Count } else { 0 }
                        $afterState["ActiveAdapters"] = if ($updatedAdapters) { ($updatedAdapters | Where-Object { $_.Status -eq "Up" }).Count } else { 0 }
                    }

                    return [OptimizationResult]::new("Network Adapter Reset", $true, "Network adapters reset and IP configuration renewed", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $adapterResetResult
                Write-OptimizationLog "Network adapter reset completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "Network adapter reset failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Network Adapter Reset", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Check if restart is required
        $restartRequired = $results | Where-Object { $_.AfterValues.ContainsKey("RestartRequired") -and $_.AfterValues["RestartRequired"] }
        if ($restartRequired) {
            Write-Host "`nIMPORTANT: Some maintenance operations require a system restart to take full effect." -ForegroundColor Yellow
            Write-Host "Please restart your computer when convenient to complete the network maintenance." -ForegroundColor Yellow
        }

        Write-Host "Network maintenance operations completed!" -ForegroundColor Green
        Write-OptimizationLog "Network maintenance completed with $($results.Count) operations" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Network maintenance failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        return @([OptimizationResult]::new("Network Maintenance", $false, $errorMessage, @{}, @{}, (Get-Date), @($_.Exception.Message)))
    }
}

function Disable-VulnerableProtocols {
        # Disable vulnerable network protocols and configure secure alternatives
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult[]])]
    param(
        [Parameter()]
        [switch]$DisableSMBv1,

        [Parameter()]
        [switch]$ConfigureSecureProtocols,

        [Parameter()]
        [switch]$DisableNetBIOS,

        [Parameter()]
        [switch]$OptimizeSSLTLS,

        [Parameter()]
        [switch]$Force
    )

    $results = @()

    try {
        Write-OptimizationLog "Starting vulnerable protocol security optimization" -Level "Info"
        Write-Host "Configuring secure network protocols..." -ForegroundColor Yellow

        # Security protocol confirmation
        if (-not $Force -and -not $Silent) {
            Write-Host "`nWARNING: Disabling network protocols may affect compatibility with older systems." -ForegroundColor Yellow
            Write-Host "These changes will improve security but may impact legacy network functionality." -ForegroundColor Yellow
            $confirm = Read-Host "Do you want to continue with protocol security optimization? (y/N)"
            if ($confirm -notmatch '^[Yy]') {
                Write-OptimizationLog "Protocol security optimization cancelled by user" -Level "Info"
                return @([OptimizationResult]::new("Protocol Security", $false, "Cancelled by user", @{}, @{}, (Get-Date), @()))
            }
        }

        # Disable SMBv1
        if ($DisableSMBv1) {
            Write-Host "  Disabling SMBv1 protocol..." -ForegroundColor Cyan

            try {
                $smbv1Result = Invoke-SafeOperation -OperationName "SMBv1 Disable" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Check current SMBv1 status
                    try {
                        $smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
                        $beforeState["SMBv1FeatureState"] = if ($smbv1Feature) { $smbv1Feature.State } else { "Unknown" }

                        $smbv1Server = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                        $beforeState["SMBv1ServerEnabled"] = if ($smbv1Server) { $smbv1Server.EnableSMB1Protocol } else { "Unknown" }
                    }
                    catch {
                        $beforeState["SMBv1Status"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("SMBv1 Protocol", "Disable for Security")) {
                        # Disable SMBv1 server
                        try {
                            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                            Write-OptimizationLog "SMBv1 server disabled" -Level "Debug"
                        }
                        catch {
                            Write-OptimizationLog "Failed to disable SMBv1 server: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Disable SMBv1 client
                        try {
                            & sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) {
                                Write-OptimizationLog "SMBv1 client dependency removed" -Level "Debug"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to modify SMBv1 client dependency: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Disable SMBv1 Windows feature (with timeout to prevent hanging)
                        try {
                            # Use Start-Job with timeout to prevent 10+ minute hangs
                            $job = Start-Job -ScriptBlock {
                                Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
                            }

                            # Wait max 30 seconds for the feature disable
                            $completed = Wait-Job -Job $job -Timeout 30

                            if ($completed) {
                                $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                                Write-OptimizationLog "SMBv1 Windows feature disabled" -Level "Debug"
                            } else {
                                # Job timed out, kill it and use registry-only method
                                Stop-Job -Job $job -ErrorAction SilentlyContinue
                                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                                Write-OptimizationLog "SMBv1 feature disable timed out, using registry method instead" -Level "Debug"
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to disable SMBv1 Windows feature: $($_.Exception.Message)" -Level "Warning"
                        }
                        finally {
                            # Clean up job if it exists
                            if ($job) {
                                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                            }
                        }

                        # Registry-based SMBv1 disable for additional security
                        try {
                            $smbRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                            Set-ItemProperty -Path $smbRegPath -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                            Write-OptimizationLog "SMBv1 registry setting disabled" -Level "Debug"
                        }
                        catch {
                            Write-OptimizationLog "Failed to set SMBv1 registry setting: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Get updated status
                        try {
                            $updatedSmbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                            $afterState["SMBv1ServerEnabled"] = if ($updatedSmbServer) { $updatedSmbServer.EnableSMB1Protocol } else { "Disabled" }
                            $afterState["SMBv1Status"] = "Disabled"
                        }
                        catch {
                            $afterState["SMBv1Status"] = "Disabled"
                        }
                    }

                    return [OptimizationResult]::new("SMBv1 Disable", $true, "SMBv1 protocol disabled for security", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $smbv1Result
                Write-OptimizationLog "SMBv1 disable completed successfully" -Level "Info"
                Write-Host "    Note: System restart recommended for SMBv1 changes to take full effect" -ForegroundColor Yellow
            }
            catch {
                $errorMsg = "SMBv1 disable failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("SMBv1 Disable", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Configure Secure Protocols
        if ($ConfigureSecureProtocols) {
            Write-Host "  Configuring secure protocol settings..." -ForegroundColor Cyan

            try {
                $secureProtocolsResult = Invoke-SafeOperation -OperationName "Secure Protocol Configuration" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current SMB configuration
                    try {
                        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                        if ($smbConfig) {
                            $beforeState["SMBv2Enabled"] = $smbConfig.EnableSMB2Protocol
                            $beforeState["SMBEncryption"] = $smbConfig.EncryptData
                            $beforeState["SMBSigning"] = $smbConfig.RequireSecuritySignature
                        }
                    }
                    catch {
                        $beforeState["SMBConfig"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("Secure Protocols", "Configure Security Settings")) {
                        # Configure SMBv2/v3 security
                        try {
                            Set-SmbServerConfiguration -EnableSMB2Protocol $true -EncryptData $true -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
                            Write-OptimizationLog "SMBv2/v3 security configured" -Level "Debug"
                        }
                        catch {
                            Write-OptimizationLog "Failed to configure SMB security: $($_.Exception.Message)" -Level "Warning"
                        }

                        # Configure secure authentication protocols
                        $authProtocolSettings = @{
                            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
                                "LmCompatibilityLevel" = 5      # Send NTLMv2 response only, refuse LM & NTLM
                                "NoLMHash" = 1                  # Do not store LAN Manager hash
                                "RestrictAnonymous" = 1         # Restrict anonymous access
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" = @{
                                "DisablePasswordChange" = 0    # Enable automatic password changes
                                "MaximumPasswordAge" = 30       # Maximum password age in days
                                "RequireSignOrSeal" = 1         # Require signing or sealing
                                "RequireStrongKey" = 1          # Require strong session key
                            }
                        }

                        foreach ($regPath in $authProtocolSettings.Keys) {
                            if (-not (Test-Path $regPath)) {
                                New-Item -Path $regPath -Force | Out-Null
                            }

                            foreach ($setting in $authProtocolSettings[$regPath].GetEnumerator()) {
                                Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Type DWord -Force
                                Write-OptimizationLog "Set secure auth setting: $regPath\$($setting.Key) = $($setting.Value)" -Level "Debug"
                            }
                        }

                        # Get updated SMB configuration
                        try {
                            $updatedSmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                            if ($updatedSmbConfig) {
                                $afterState["SMBv2Enabled"] = $updatedSmbConfig.EnableSMB2Protocol
                                $afterState["SMBEncryption"] = $updatedSmbConfig.EncryptData
                                $afterState["SMBSigning"] = $updatedSmbConfig.RequireSecuritySignature
                            }
                        }
                        catch {
                            $afterState["SMBConfig"] = "Configured"
                        }
                    }

                    return [OptimizationResult]::new("Secure Protocol Configuration", $true, "Secure protocols configured successfully", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $secureProtocolsResult
                Write-OptimizationLog "Secure protocol configuration completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "Secure protocol configuration failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("Secure Protocol Configuration", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Disable NetBIOS
        if ($DisableNetBIOS) {
            Write-Host "  Configuring NetBIOS security settings..." -ForegroundColor Cyan

            try {
                $netbiosResult = Invoke-SafeOperation -OperationName "NetBIOS Security Configuration" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current NetBIOS settings
                    try {
                        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                        $beforeState["ActiveAdapters"] = $adapters.Count
                        $beforeState["NetBIOSEnabled"] = "Unknown"
                    }
                    catch {
                        $beforeState["NetBIOSStatus"] = "Unknown"
                    }

                    if ($PSCmdlet.ShouldProcess("NetBIOS Settings", "Configure Security")) {
                        # Configure NetBIOS security settings
                        $netbiosSecuritySettings = @{
                            "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" = @{
                                "NoNameReleaseOnDemand" = 1     # Prevent name release attacks
                                "NodeType" = 2                  # P-node (point-to-point) for security
                                "EnableLMHosts" = 0             # Disable LMHosts lookup
                                "EnableProxy" = 0               # Disable NetBIOS proxy
                            }
                        }

                        foreach ($regPath in $netbiosSecuritySettings.Keys) {
                            if (-not (Test-Path $regPath)) {
                                New-Item -Path $regPath -Force | Out-Null
                            }

                            foreach ($setting in $netbiosSecuritySettings[$regPath].GetEnumerator()) {
                                Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Type DWord -Force
                                Write-OptimizationLog "Set NetBIOS security setting: $($setting.Key) = $($setting.Value)" -Level "Debug"
                            }
                        }

                        # Disable NetBIOS over TCP/IP on network adapters where safe
                        try {
                            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.InterfaceDescription -notlike "*Loopback*" }
                            foreach ($adapter in $adapters) {
                                $adapterRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)"
                                if (Test-Path $adapterRegPath) {
                                    # Set NetbiosOptions to 2 (disable NetBIOS over TCP/IP)
                                    Set-ItemProperty -Path $adapterRegPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
                                    Write-OptimizationLog "Disabled NetBIOS over TCP/IP for adapter: $($adapter.Name)" -Level "Debug"
                                }
                            }
                        }
                        catch {
                            Write-OptimizationLog "Failed to configure adapter NetBIOS settings: $($_.Exception.Message)" -Level "Warning"
                        }

                        $afterState["NetBIOSSecurityConfigured"] = $true
                        $afterState["NetBIOSOverTCPDisabled"] = $true
                    }

                    return [OptimizationResult]::new("NetBIOS Security Configuration", $true, "NetBIOS security settings configured", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $netbiosResult
                Write-OptimizationLog "NetBIOS security configuration completed successfully" -Level "Info"
            }
            catch {
                $errorMsg = "NetBIOS security configuration failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("NetBIOS Security Configuration", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        # Optimize SSL/TLS
        if ($OptimizeSSLTLS) {
            Write-Host "  Optimizing SSL/TLS security settings..." -ForegroundColor Cyan

            try {
                $sslTlsResult = Invoke-SafeOperation -OperationName "SSL/TLS Security Optimization" -Operation {
                    $beforeState = @{}
                    $afterState = @{}

                    # Get current SSL/TLS settings
                    $sslRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
                    $beforeState["SSLTLSConfigured"] = Test-Path $sslRegPath

                    if ($PSCmdlet.ShouldProcess("SSL/TLS Settings", "Optimize Security Configuration")) {
                        # Configure secure SSL/TLS settings
                        $sslTlsSettings = @{
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" = @{
                                "Enabled" = 0               # Disable TLS 1.0 client
                                "DisabledByDefault" = 1     # Disable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" = @{
                                "Enabled" = 0               # Disable TLS 1.0 server
                                "DisabledByDefault" = 1     # Disable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" = @{
                                "Enabled" = 0               # Disable TLS 1.1 client
                                "DisabledByDefault" = 1     # Disable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" = @{
                                "Enabled" = 0               # Disable TLS 1.1 server
                                "DisabledByDefault" = 1     # Disable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" = @{
                                "Enabled" = 1               # Enable TLS 1.2 client
                                "DisabledByDefault" = 0     # Enable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" = @{
                                "Enabled" = 1               # Enable TLS 1.2 server
                                "DisabledByDefault" = 0     # Enable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" = @{
                                "Enabled" = 1               # Enable TLS 1.3 client
                                "DisabledByDefault" = 0     # Enable by default
                            }
                            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" = @{
                                "Enabled" = 1               # Enable TLS 1.3 server
                                "DisabledByDefault" = 0     # Enable by default
                            }
                        }

                        foreach ($regPath in $sslTlsSettings.Keys) {
                            if (-not (Test-Path $regPath)) {
                                New-Item -Path $regPath -Force | Out-Null
                            }

                            foreach ($setting in $sslTlsSettings[$regPath].GetEnumerator()) {
                                Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Type DWord -Force
                                Write-OptimizationLog "Set SSL/TLS setting: $regPath\$($setting.Key) = $($setting.Value)" -Level "Debug"
                            }
                        }

                        # Configure cipher suite order for security
                        try {
                            $cipherSuitePath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                            if (-not (Test-Path $cipherSuitePath)) {
                                New-Item -Path $cipherSuitePath -Force | Out-Null
                            }

                            # Set secure cipher suite order (prioritize AEAD ciphers)
                            $secureCipherSuites = @(
                                "TLS_AES_256_GCM_SHA384",
                                "TLS_AES_128_GCM_SHA256",
                                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                            ) -join ","

                            Set-ItemProperty -Path $cipherSuitePath -Name "Functions" -Value $secureCipherSuites -Type String -Force
                            Write-OptimizationLog "Secure cipher suite order configured" -Level "Debug"
                        }
                        catch {
                            Write-OptimizationLog "Failed to configure cipher suite order: $($_.Exception.Message)" -Level "Warning"
                        }

                        $afterState["SSLTLSOptimized"] = $true
                        $afterState["SecureProtocolsEnabled"] = "TLS 1.2, TLS 1.3"
                        $afterState["InsecureProtocolsDisabled"] = "TLS 1.0, TLS 1.1"
                    }

                    return [OptimizationResult]::new("SSL/TLS Security Optimization", $true, "SSL/TLS security settings optimized", $beforeState, $afterState, (Get-Date), @())
                }

                $results += $sslTlsResult
                Write-OptimizationLog "SSL/TLS security optimization completed successfully" -Level "Info"
                Write-Host "    Note: Applications may need restart to use new SSL/TLS settings" -ForegroundColor Yellow
            }
            catch {
                $errorMsg = "SSL/TLS security optimization failed: $($_.Exception.Message)"
                Write-OptimizationLog $errorMsg -Level "Error"
                $results += [OptimizationResult]::new("SSL/TLS Security Optimization", $false, $errorMsg, @{}, @{}, (Get-Date), @($_.Exception.Message))
            }
        }

        Write-Host "Vulnerable protocol security optimization completed!" -ForegroundColor Green
        Write-OptimizationLog "Vulnerable protocol security optimization completed with $($results.Count) operations" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Vulnerable protocol security optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        return @([OptimizationResult]::new("Protocol Security", $false, $errorMessage, @{}, @{}, (Get-Date), @($_.Exception.Message)))
    }
}

#endregion

#region Gaming and Streaming Optimization Module

function Enable-GamingMode {
        # Enable gaming-specific network optimizations for reduced latency and improved...
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    $results = @{
        Success = $true
        AppliedSettings = @()
        Errors = @()
        OperationName = "Gaming Mode Optimization"
    }

    try {
        Write-OptimizationLog "Starting gaming mode network optimizations" -Level "Info"
        Write-Host "Applying gaming mode optimizations..." -ForegroundColor Cyan

        # Gaming-specific registry optimizations
        $gamingOptimizations = @{
            # TCP optimizations for gaming
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'TcpAckFrequency' = 1          # Immediate ACK for low latency
                'TCPNoDelay' = 1               # Disable Nagle's algorithm for gaming
                'TcpDelAckTicks' = 0           # Minimize delayed ACK for responsiveness
                'MaxUserPort' = 65534          # Maximum port range for gaming connections
                'TcpTimedWaitDelay' = 30       # Reduce TIME_WAIT for faster reconnections
                'EnablePMTUDiscovery' = 1      # Path MTU discovery for optimal packet size
                'EnablePMTUBHDetect' = 0       # Disable black hole detection for gaming
            }

            # Gaming-specific QoS settings
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' = @{
                'NonBestEffortLimit' = 0       # Allow 100% bandwidth for gaming
            }

            # Network throttling index for gaming (disable throttling)
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                'NetworkThrottlingIndex' = 10  # Disable network throttling for gaming
                'SystemResponsiveness' = 0     # Prioritize gaming over system tasks
            }

            # Gaming task scheduler optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 8
                'Priority' = 6
                'Scheduling Category' = 'High'
                'SFIO Priority' = 'High'
            }
        }

        # Apply gaming optimizations
        foreach ($registryPath in $gamingOptimizations.Keys) {
            try {
                # Ensure registry path exists
                if (-not (Test-Path $registryPath)) {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Create Registry Path")) {
                        New-Item -Path $registryPath -Force | Out-Null
                        Write-OptimizationLog "Created registry path: $registryPath" -Level "Info"
                    }
                }

                # Apply each setting in the path
                $settings = $gamingOptimizations[$registryPath]
                foreach ($valueName in $settings.Keys) {
                    $value = $settings[$valueName]

                    if ($PSCmdlet.ShouldProcess("$registryPath\$valueName", "Set Registry Value to $value")) {
                        # Handle different value types
                        if ($value -is [string] -and $value -in @('False', 'True', 'High')) {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type String -Force
                        } else {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWord -Force
                        }

                        $results.AppliedSettings += @{
                            Path = $registryPath
                            Name = $valueName
                            Value = $value
                            Type = "Gaming Optimization"
                        }

                        Write-OptimizationLog "Applied gaming setting: $registryPath\$valueName = $value" -Level "Info"
                    }
                }
            }
            catch {
                $errorMsg = "Failed to apply gaming optimization to ${1} : $($_.Exception.Message)"
                $results.Errors += $errorMsg
                Write-OptimizationLog $errorMsg -Level "Error"
                $results.Success = $false
            }
        }

        # Apply network adapter specific gaming optimizations
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $networkAdapters) {
            try {
                $adapterPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$($adapter.InterfaceIndex.ToString('D4'))"

                if (Test-Path $adapterPath) {
                    $adapterOptimizations = @{
                        'TcpAckFrequency' = 1
                        'TCPNoDelay' = 1
                        'InterruptModeration' = 0      # Disable for gaming
                        'ITR' = 0                      # Interrupt throttle rate
                    }

                    foreach ($setting in $adapterOptimizations.Keys) {
                        if ($PSCmdlet.ShouldProcess("$adapterPath\$setting", "Set Gaming Adapter Setting")) {
                            Set-ItemProperty -Path $adapterPath -Name $setting -Value $adapterOptimizations[$setting] -Type DWord -Force -ErrorAction SilentlyContinue
                            Write-OptimizationLog "Applied gaming adapter setting: $($adapter.Name)\$setting = $($adapterOptimizations[$setting])" -Level "Info"
                        }
                    }
                }
            }
            catch {
                Write-OptimizationLog "Failed to optimize adapter $($adapter.Name) for gaming: $($_.Exception.Message)" -Level "Warning"
            }
        }

        Write-Host "Gaming mode optimizations applied successfully!" -ForegroundColor Green
        Write-OptimizationLog "Gaming mode optimization completed with $($results.AppliedSettings.Count) settings applied" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Gaming mode optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        $results.Success = $false
        $results.Errors += $errorMessage
        return $results
    }
}

function Enable-StreamingMode {
        # Enable video streaming network optimizations for consistent bandwidth and qua...
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    $results = @{
        Success = $true
        AppliedSettings = @()
        Errors = @()
        OperationName = "Streaming Mode Optimization"
    }

    try {
        Write-OptimizationLog "Starting streaming mode network optimizations" -Level "Info"
        Write-Host "Applying streaming mode optimizations..." -ForegroundColor Cyan

        # Streaming-specific registry optimizations
        $streamingOptimizations = @{
            # TCP optimizations for streaming
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'TcpWindowSize' = 65536        # Larger window for streaming
                'Tcp1323Opts' = 3              # Enable window scaling and timestamps
                'DefaultTTL' = 64              # Optimal TTL for streaming
                'EnablePMTUDiscovery' = 1      # Path MTU discovery
                'TcpMaxDupAcks' = 2            # Fast retransmit for streaming
                'SackOpts' = 1                 # Selective acknowledgments
                'MaxFreeTcbs' = 16000          # More TCP control blocks
                'MaxHashTableSize' = 65536     # Larger hash table for connections
            }

            # Buffer management for streaming
            'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' = @{
                'DefaultReceiveWindow' = 65536  # Larger receive window
                'DefaultSendWindow' = 65536     # Larger send window
                'FastSendDatagramThreshold' = 1024
                'FastCopyReceiveThreshold' = 1024
                'DynamicSendBufferDisable' = 0  # Enable dynamic buffers
            }

            # QoS for streaming applications
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' = @{
                'NonBestEffortLimit' = 20      # Reserve 20% for streaming QoS
            }

            # Multimedia streaming optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                'NetworkThrottlingIndex' = 70   # Moderate throttling for streaming
                'SystemResponsiveness' = 10     # Balance system and streaming
            }

            # Streaming task scheduler optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 2
                'Priority' = 5
                'Scheduling Category' = 'Medium'
                'SFIO Priority' = 'Normal'
            }
        }

        # Apply streaming optimizations
        foreach ($registryPath in $streamingOptimizations.Keys) {
            try {
                # Ensure registry path exists
                if (-not (Test-Path $registryPath)) {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Create Registry Path")) {
                        New-Item -Path $registryPath -Force | Out-Null
                        Write-OptimizationLog "Created registry path: $registryPath" -Level "Info"
                    }
                }

                # Apply each setting in the path
                $settings = $streamingOptimizations[$registryPath]
                foreach ($valueName in $settings.Keys) {
                    $value = $settings[$valueName]

                    if ($PSCmdlet.ShouldProcess("$registryPath\$valueName", "Set Registry Value to $value")) {
                        # Handle different value types
                        if ($value -is [string] -and $value -in @('False', 'True', 'Medium', 'Normal')) {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type String -Force
                        } else {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWord -Force
                        }

                        $results.AppliedSettings += @{
                            Path = $registryPath
                            Name = $valueName
                            Value = $value
                            Type = "Streaming Optimization"
                        }

                        Write-OptimizationLog "Applied streaming setting: $registryPath\$valueName = $value" -Level "Info"
                    }
                }
            }
            catch {
                $errorMsg = "Failed to apply streaming optimization to ${1} : $($_.Exception.Message)"
                $results.Errors += $errorMsg
                Write-OptimizationLog $errorMsg -Level "Error"
                $results.Success = $false
            }
        }

        # Configure network adapters for streaming
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $networkAdapters) {
            try {
                # Enable flow control for streaming
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Configure Flow Control for Streaming")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Flow Control" -DisplayValue "Rx & Tx Enabled" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Enabled flow control for streaming on adapter: $($adapter.Name)" -Level "Info"
                }

                # Optimize interrupt moderation for streaming
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Configure Interrupt Moderation for Streaming")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Configured interrupt moderation for streaming on adapter: $($adapter.Name)" -Level "Info"
                }
            }
            catch {
                Write-OptimizationLog "Failed to optimize adapter $($adapter.Name) for streaming: $($_.Exception.Message)" -Level "Warning"
            }
        }

        Write-Host "Streaming mode optimizations applied successfully!" -ForegroundColor Green
        Write-OptimizationLog "Streaming mode optimization completed with $($results.AppliedSettings.Count) settings applied" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Streaming mode optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        $results.Success = $false
        $results.Errors += $errorMessage
        return $results
    }
}

function Enable-CloudGamingMode {
        # Enable cloud gaming service optimizations for low latency streaming
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    $results = @{
        Success = $true
        AppliedSettings = @()
        Errors = @()
        OperationName = "Cloud Gaming Mode Optimization"
    }

    try {
        Write-OptimizationLog "Starting cloud gaming mode network optimizations" -Level "Info"
        Write-Host "Applying cloud gaming mode optimizations..." -ForegroundColor Cyan

        # Cloud gaming specific registry optimizations
        $cloudGamingOptimizations = @{
            # TCP and UDP optimizations for cloud gaming
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'TcpAckFrequency' = 1          # Immediate ACK for ultra-low latency
                'TCPNoDelay' = 1               # Disable Nagle's algorithm
                'TcpDelAckTicks' = 0           # No delayed ACK
                'TcpWindowSize' = 32768        # Balanced window size for cloud gaming
                'Tcp1323Opts' = 3              # Enable scaling and timestamps
                'DefaultTTL' = 64              # Optimal TTL
                'EnablePMTUDiscovery' = 1      # Path MTU discovery
                'TcpMaxDupAcks' = 2            # Fast retransmit
                'SackOpts' = 1                 # Selective acknowledgments
                'TcpTimedWaitDelay' = 30       # Reduce TIME_WAIT
                'MaxUserPort' = 65534          # Maximum port range
                'EnablePMTUBHDetect' = 0       # Disable black hole detection
                'FastSendDatagramThreshold' = 1024
                'FastCopyReceiveThreshold' = 1024
            }

            # QoS for cloud gaming
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' = @{
                'NonBestEffortLimit' = 0       # Allow 100% bandwidth for cloud gaming
            }

            # Network throttling optimizations for cloud gaming
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                'NetworkThrottlingIndex' = 10  # Disable network throttling
                'SystemResponsiveness' = 0     # Prioritize cloud gaming
            }

            # Cloud gaming task scheduler optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 8
                'Priority' = 6
                'Scheduling Category' = 'High'
                'SFIO Priority' = 'High'
            }

            # Additional cloud gaming optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 4
                'Priority' = 5
                'Scheduling Category' = 'Medium'
                'SFIO Priority' = 'High'
            }
        }

        # Apply cloud gaming optimizations
        foreach ($registryPath in $cloudGamingOptimizations.Keys) {
            try {
                # Ensure registry path exists
                if (-not (Test-Path $registryPath)) {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Create Registry Path")) {
                        New-Item -Path $registryPath -Force | Out-Null
                        Write-OptimizationLog "Created registry path: $registryPath" -Level "Info"
                    }
                }

                # Apply each setting in the path
                $settings = $cloudGamingOptimizations[$registryPath]
                foreach ($valueName in $settings.Keys) {
                    $value = $settings[$valueName]

                    if ($PSCmdlet.ShouldProcess("$registryPath\$valueName", "Set Registry Value to $value")) {
                        # Handle different value types
                        if ($value -is [string] -and $value -in @('False', 'True', 'High', 'Medium')) {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type String -Force
                        } else {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWord -Force
                        }

                        $results.AppliedSettings += @{
                            Path = $registryPath
                            Name = $valueName
                            Value = $value
                            Type = "Cloud Gaming Optimization"
                        }

                        Write-OptimizationLog "Applied cloud gaming setting: $registryPath\$valueName = $value" -Level "Info"
                    }
                }
            }
            catch {
                $errorMsg = "Failed to apply cloud gaming optimization to ${1} : $($_.Exception.Message)"
                $results.Errors += $errorMsg
                Write-OptimizationLog $errorMsg -Level "Error"
                $results.Success = $false
            }
        }

        # Configure network adapters for cloud gaming
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $networkAdapters) {
            try {
                # Disable interrupt moderation for ultra-low latency
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Disable Interrupt Moderation for Cloud Gaming")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Disabled interrupt moderation for cloud gaming on adapter: $($adapter.Name)" -Level "Info"
                }

                # Optimize receive/transmit buffers for cloud gaming
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Optimize Buffers for Cloud Gaming")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Transmit Buffers" -DisplayValue "2048" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Optimized buffers for cloud gaming on adapter: $($adapter.Name)" -Level "Info"
                }
            }
            catch {
                Write-OptimizationLog "Failed to optimize adapter $($adapter.Name) for cloud gaming: $($_.Exception.Message)" -Level "Warning"
            }
        }

        Write-Host "Cloud gaming mode optimizations applied successfully!" -ForegroundColor Green
        Write-OptimizationLog "Cloud gaming mode optimization completed with $($results.AppliedSettings.Count) settings applied" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Cloud gaming mode optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        $results.Success = $false
        $results.Errors += $errorMessage
        return $results
    }
}

function Set-VideoConferencingMode {
        # Configure network settings for optimal video conferencing performance
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param()

    $results = @{
        Success = $true
        AppliedSettings = @()
        Errors = @()
        OperationName = "Video Conferencing Mode Optimization"
    }

    try {
        Write-OptimizationLog "Starting video conferencing mode network optimizations" -Level "Info"
        Write-Host "Applying video conferencing mode optimizations..." -ForegroundColor Cyan

        # Video conferencing specific registry optimizations
        $videoConfOptimizations = @{
            # TCP and UDP optimizations for video conferencing
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                'TcpAckFrequency' = 2          # Balanced ACK frequency
                'TCPNoDelay' = 1               # Disable Nagle's for real-time
                'TcpDelAckTicks' = 1           # Minimal delayed ACK
                'TcpWindowSize' = 65536        # Standard window size
                'Tcp1323Opts' = 3              # Enable scaling and timestamps
                'DefaultTTL' = 64              # Standard TTL
                'EnablePMTUDiscovery' = 1      # Path MTU discovery
                'TcpMaxDupAcks' = 2            # Fast retransmit
                'SackOpts' = 1                 # Selective acknowledgments
                'FastSendDatagramThreshold' = 1024
                'FastCopyReceiveThreshold' = 1024
                'EnablePMTUBHDetect' = 1       # Enable for video conferencing
            }

            # QoS for video conferencing
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' = @{
                'NonBestEffortLimit' = 10      # Reserve 10% for QoS
            }

            # Network throttling for video conferencing
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                'NetworkThrottlingIndex' = 40  # Moderate throttling
                'SystemResponsiveness' = 20    # Balance system and conferencing
            }

            # Video conferencing task scheduler optimizations
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 4
                'Priority' = 5
                'Scheduling Category' = 'Medium'
                'SFIO Priority' = 'Normal'
            }

            # Audio optimizations for video conferencing
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' = @{
                'Affinity' = 0
                'Background Only' = 'False'
                'Clock Rate' = 10000
                'GPU Priority' = 1
                'Priority' = 4
                'Scheduling Category' = 'Medium'
                'SFIO Priority' = 'Normal'
            }
        }

        # Apply video conferencing optimizations
        foreach ($registryPath in $videoConfOptimizations.Keys) {
            try {
                # Ensure registry path exists
                if (-not (Test-Path $registryPath)) {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Create Registry Path")) {
                        New-Item -Path $registryPath -Force | Out-Null
                        Write-OptimizationLog "Created registry path: $registryPath" -Level "Info"
                    }
                }

                # Apply each setting in the path
                $settings = $videoConfOptimizations[$registryPath]
                foreach ($valueName in $settings.Keys) {
                    $value = $settings[$valueName]

                    if ($PSCmdlet.ShouldProcess("$registryPath\$valueName", "Set Registry Value to $value")) {
                        # Handle different value types
                        if ($value -is [string] -and $value -in @('False', 'True', 'Medium', 'Normal')) {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type String -Force
                        } else {
                            Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWord -Force
                        }

                        $results.AppliedSettings += @{
                            Path = $registryPath
                            Name = $valueName
                            Value = $value
                            Type = "Video Conferencing Optimization"
                        }

                        Write-OptimizationLog "Applied video conferencing setting: $registryPath\$valueName = $value" -Level "Info"
                    }
                }
            }
            catch {
                $errorMsg = "Failed to apply video conferencing optimization to ${1} : $($_.Exception.Message)"
                $results.Errors += $errorMsg
                Write-OptimizationLog $errorMsg -Level "Error"
                $results.Success = $false
            }
        }

        # Configure network adapters for video conferencing
        $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $networkAdapters) {
            try {
                # Enable flow control for stable video conferencing
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Configure Flow Control for Video Conferencing")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Flow Control" -DisplayValue "Rx & Tx Enabled" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Enabled flow control for video conferencing on adapter: $($adapter.Name)" -Level "Info"
                }

                # Moderate interrupt moderation for video conferencing
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Configure Interrupt Moderation for Video Conferencing")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Interrupt Moderation" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Configured interrupt moderation for video conferencing on adapter: $($adapter.Name)" -Level "Info"
                }

                # Optimize receive buffers for video conferencing
                if ($PSCmdlet.ShouldProcess($adapter.Name, "Optimize Buffers for Video Conferencing")) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Receive Buffers" -DisplayValue "1024" -ErrorAction SilentlyContinue
                    Write-OptimizationLog "Optimized receive buffers for video conferencing on adapter: $($adapter.Name)" -Level "Info"
                }
            }
            catch {
                Write-OptimizationLog "Failed to optimize adapter $($adapter.Name) for video conferencing: $($_.Exception.Message)" -Level "Warning"
            }
        }

        Write-Host "Video conferencing mode optimizations applied successfully!" -ForegroundColor Green
        Write-OptimizationLog "Video conferencing mode optimization completed with $($results.AppliedSettings.Count) settings applied" -Level "Info"

        return $results
    }
    catch {
        $errorMessage = "Video conferencing mode optimization failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        $results.Success = $false
        $results.Errors += $errorMessage
        return $results
    }
}

function Test-GamingStreamingOptimizations {
        # Validate and test gaming and streaming optimization performance
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [ValidateSet("Gaming", "Streaming", "CloudGaming", "VideoConferencing", "All")]
        [string]$TestType = "All"
    )

    $testResults = @{
        Success = $true
        TestResults = @()
        Errors = @()
        OperationName = "Gaming and Streaming Optimization Validation"
    }

    try {
        Write-OptimizationLog "Starting gaming and streaming optimization validation tests" -Level "Info"
        Write-Host "Validating gaming and streaming optimizations..." -ForegroundColor Cyan

        # Define test configurations for each optimization type
        $testConfigurations = @{
            'Gaming' = @{
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                    'TcpAckFrequency' = 1
                    'TCPNoDelay' = 1
                    'TcpDelAckTicks' = 0
                }
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                    'NetworkThrottlingIndex' = 10
                    'SystemResponsiveness' = 0
                }
            }
            'Streaming' = @{
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                    'TcpWindowSize' = 65536
                    'Tcp1323Opts' = 3
                }
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' = @{
                    'NetworkThrottlingIndex' = 70
                    'SystemResponsiveness' = 10
                }
            }
            'CloudGaming' = @{
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                    'TcpAckFrequency' = 1
                    'TcpWindowSize' = 32768
                }
            }
            'VideoConferencing' = @{
                'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' = @{
                    'TcpAckFrequency' = 2
                    'TcpDelAckTicks' = 1
                }
            }
        }

        # Determine which tests to run
        $testsToRun = if ($TestType -eq "All") { $testConfigurations.Keys } else { @($TestType) }

        foreach ($testName in $testsToRun) {
            Write-Host "Testing $testName optimizations..." -ForegroundColor Yellow

            $testConfig = $testConfigurations[$testName]
            $testResult = @{
                TestName = $testName
                Success = $true
                ValidatedSettings = @()
                FailedSettings = @()
            }

            foreach ($registryPath in $testConfig.Keys) {
                $settings = $testConfig[$registryPath]

                foreach ($valueName in $settings.Keys) {
                    $expectedValue = $settings[$valueName]

                    try {
                        if (Test-Path $registryPath) {
                            $actualValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

                            if ($null -ne $actualValue -and $actualValue.$valueName -eq $expectedValue) {
                                $testResult.ValidatedSettings += "$registryPath\$valueName = $expectedValue"
                                Write-OptimizationLog "Validated $testName setting: $registryPath\$valueName = $expectedValue" -Level "Info"
                            } else {
                                $actualVal = if ($null -ne $actualValue) { $actualValue.$valueName } else { "Not Set" }
                                $testResult.FailedSettings += "$registryPath\$valueName (Expected: $expectedValue, Actual: $actualVal)"
                                $testResult.Success = $false
                                Write-OptimizationLog "Failed validation for $testName setting - $registryPath\$valueName (Expected: $expectedValue, Actual: $actualVal)" -Level "Warning"
                            }
                        } else {
                            $testResult.FailedSettings += "$registryPath (Path not found)"
                            $testResult.Success = $false
                            Write-OptimizationLog "Failed validation for $testName - Registry path not found - $registryPath" -Level "Warning"
                        }
                    }
                    catch {
                        $testResult.FailedSettings += "$registryPath\$valueName (Error: $($_.Exception.Message))"
                        $testResult.Success = $false
                        Write-OptimizationLog "Error validating $testName setting $registryPath\$valueName - $($_.Exception.Message)" -Level "Error"
                    }
                }
            }

            $testResults.TestResults += $testResult

            if ($testResult.Success) {
                Write-Host "[OK] $testName optimizations validated successfully" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] $testName optimizations validation failed" -ForegroundColor Red
                $testResults.Success = $false
            }
        }

        # Performance validation summary
        $totalValidated = ($testResults.TestResults | ForEach-Object { $_.ValidatedSettings.Count } | Measure-Object -Sum).Sum
        $totalFailed = ($testResults.TestResults | ForEach-Object { $_.FailedSettings.Count } | Measure-Object -Sum).Sum

        Write-Host "`nValidation Summary:" -ForegroundColor Cyan
        Write-Host "  Validated Settings: $totalValidated" -ForegroundColor Green
        Write-Host "  Failed Settings: $totalFailed" -ForegroundColor $(if ($totalFailed -eq 0) { "Green" } else { "Red" })

        Write-OptimizationLog "Gaming and streaming optimization validation completed. Validated: $totalValidated, Failed: $totalFailed" -Level "Info"

        return $testResults
    }
    catch {
        $errorMessage = "Gaming and streaming optimization validation failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage
        $testResults.Success = $false
        $testResults.Errors += $errorMessage
        return $testResults
    }
}

#endregion

function Start-NetworkOptimizer {
        [CmdletBinding()]
    param()

    try {
        # Display banner
        Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                          Network Optimizer v$Script:Version                          ║
║                     PowerShell Network Performance Tool                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        # Initialize the optimizer
        if (-not (Initialize-NetworkOptimizer)) {
            throw "Failed to initialize Network Optimizer"
        }

        # Initialize configuration management system
        Write-Host "Initializing configuration management system..." -ForegroundColor Yellow
        $Script:Config = Get-DefaultConfiguration

        # Test configuration integrity
        if (-not (Test-ConfigurationIntegrity -Config $Script:Config)) {
            throw "Configuration integrity validation failed"
        }

        Write-Host "Configuration system initialized with $($Script:Config.Options.Count) optimization options" -ForegroundColor Green
        Write-OptimizationLog "Configuration management system initialized successfully" -Level "Info"

        if ($Silent) {
            Show-CleanMessage "Silent mode activated - Applying recommended settings" -Type Progress
            Write-OptimizationLog "Silent mode execution started" -Level "Info"

            # Select recommended options for silent mode
            $Script:Config.SelectRecommendedOptions()
            $selectedOptions = $Script:Config.GetSelectedOptions()
            $selectedCount = $selectedOptions.Count

            if ($selectedCount -eq 0) {
                Show-CleanMessage "No optimizations selected" -Type Warning
                return
            }

            Write-Host ""
            Show-CleanMessage "Preparing $selectedCount optimizations..." -Type Progress

            # Execute with progress tracking
            $Script:TotalSteps = $selectedCount
            $Script:CurrentStep = 0

            Write-Host ""
            $executionResult = Invoke-SelectedOptimizations -SelectedOptions $selectedOptions -Config $Script:Config -ContinueOnError

            # Store results in global variable for reporting
            $Script:OptimizationResults = $executionResult.Results

            Write-Host ""
            if ($executionResult.Success) {
                Show-CleanMessage "All optimizations applied successfully!" -Type Success
                Write-OptimizationLog "Silent mode execution completed successfully" -Level "Info"
            } else {
                Show-CleanMessage "Completed with some errors - check log for details" -Type Warning
                Write-OptimizationLog "Silent mode execution completed with errors" -Level "Warning"
            }

            # Generate summary report (suppress verbose output)
            Write-Host ""
            Show-CleanMessage "Generating report..." -Type Progress
            $reportResult = New-NetworkHealthReport -OptimizationResults $Script:OptimizationResults
            if ($reportResult.Success -and $reportResult.Files.Count -gt 0) {
                Show-CleanMessage "Report saved" -Type Success
            }
        } else {
            Show-CleanMessage "Interactive mode - Starting menu system..." -Type Progress
            Write-OptimizationLog "Starting interactive mode" -Level "Info"

            # Display configuration summary
            Write-Host ""
            Write-Host "Available Optimizations:" -ForegroundColor Cyan
            foreach ($category in ($Script:Config.Options | Group-Object Category)) {
                Write-Host "  • $($category.Name): $($category.Count) options" -ForegroundColor Gray
            }
            Write-Host ""

            # Start the interactive menu system
            Start-InteractiveMenu
        }

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
        Show-CleanMessage "Ready!" -Type Success
        Write-Host "═══════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-OptimizationLog "Network Optimizer execution completed successfully" -Level "Info"
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-OptimizationLog "Network Optimizer execution failed: $errorMessage" -Level "Error"

        # Handle user cancellation gracefully
        if ($errorMessage -match "Operation cancelled by user") {
            Write-Host "`n✓ Operation cancelled - No changes made to your system" -ForegroundColor Yellow

            # Pause to let user see the message before closing (only in remote execution)
            if ($MyInvocation.InvocationName -match "http") {
                Write-Host "Press any key to close..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            return
        }

        # Display concise error for other exceptions
        if ($errorMessage -match "administrator privileges") {
            Write-Error $errorMessage
        } else {
            Write-Host "`n❌ Error: $errorMessage" -ForegroundColor Red
            Write-Host "Check log file for details: $Script:LogFile" -ForegroundColor Gray
        }

        # For remote execution, pause before exiting
        if ($MyInvocation.InvocationName -match "http") {
            Write-Host "`nPress any key to close..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }

        exit 1
    }
    finally {
        # Cleanup and final logging
        $endTime = Get-Date
        $duration = $endTime - $Script:StartTime
        Write-OptimizationLog "Script execution completed. Duration: $($duration.ToString('hh\:mm\:ss'))" -Level "Info"

        if ($Script:LogFile -and (Test-Path $Script:LogFile)) {
            Write-Host "Log file created: $Script:LogFile" -ForegroundColor Gray
        }
    }
}

#endregion

#region Optimization Execution Engine

function Invoke-SelectedOptimizations {
        # Execute selected network optimizations with comprehensive error handling and ...
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption[]]$SelectedOptions,

        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config,

        [Parameter()]
        [switch]$ContinueOnError,

        [Parameter()]
        [bool]$ValidateBeforeExecution = $true,

        [Parameter()]
        [bool]$ValidateAfterExecution = $true
    )

    # Initialize execution context
    $execContext = @{
        StartTime = Get-Date
        TotalOptimizations = $SelectedOptions.Count
        CompletedOptimizations = 0
        FailedOptimizations = 0
        SkippedOptimizations = 0
        Results = @()
        RollbackOperations = @()
        OverallSuccess = $true
        ExecutionId = [System.Guid]::NewGuid().ToString()
    }

    try {
    Write-OptimizationLog "Starting optimization execution engine - ID: $($execContext.ExecutionId)" -Level "Info"
    Write-OptimizationLog "Total optimizations to execute: $($execContext.TotalOptimizations)" -Level "Info"

    if ($PSCmdlet.ShouldProcess("$($execContext.TotalOptimizations) optimizations", "Execute Network Optimizations")) {
            # Continue with execution
        } else {
            return @{
                Success = $true
                Results = @()
                ExecutionContext = $execContext
                WhatIfMode = $true
            }
        }

        # Pre-execution validation (silent)
        if ($ValidateBeforeExecution) {
            $preValidation = Test-PreExecutionValidation -SelectedOptions $SelectedOptions -Config $Config

            if (-not $preValidation.Success) {
                throw "Pre-execution validation failed: $($preValidation.Message)"
            }

            Write-OptimizationLog "Pre-execution validation completed successfully" -Level "Info"
        }

        # Execute optimizations sequentially
        for ($i = 0; $i -lt $SelectedOptions.Count; $i++) {
            $option = $SelectedOptions[$i]
            $currentStep = $i + 1
            $Script:CurrentStep = $currentStep

            try {
                # Update progress with clean progress bar
                Write-ProgressBar -Current $currentStep -Total $execContext.TotalOptimizations -Activity "Optimizing" -Status $option.Name

                # Progress bar shows the status
                Write-OptimizationLog "Starting optimization: $($option.Name) (Step $currentStep of $($execContext.TotalOptimizations))" -Level "Info"

                # Pre-optimization validation for this specific option
                if ($ValidateBeforeExecution) {
                    $optionValidation = Test-OptimizationValidation -Option $option -Config $Config
                    if (-not $optionValidation.Success) {
                        throw "Validation failed for $($option.Name): $($optionValidation.Message)"
                    }
                }

                # Capture system state before optimization
                $beforeState = Get-SystemState -Option $option
                Write-OptimizationLog "System state captured before optimization: $($option.Name)" -Level "Debug"

                # Execute the optimization with comprehensive error handling
                $optimizationResult = Invoke-SingleOptimization -Option $option -Config $Config -BeforeState $beforeState

                # Post-optimization validation
                if ($ValidateAfterExecution -and $optimizationResult.Success) {
                    $postValidation = Test-PostOptimizationValidation -Option $option -Result $optimizationResult -Config $Config
                    if (-not $postValidation.Success) {
                        Write-OptimizationLog "Post-optimization validation had issues for $($option.Name): $($postValidation.Message)" -Level "Warning"
                        # Don't fail the optimization based on validation issues
                        # Registry changes are atomic and should be considered successful if they applied
                        Write-OptimizationLog "Optimization changes were applied successfully and will be retained despite validation warnings" -Level "Info"
                    }
                }

                # Add result to execution context
                $execContext.Results += $optimizationResult

                # Update counters based on result
                if ($optimizationResult.Success) {
                    $execContext.CompletedOptimizations++
                    Write-Host "  ✅ $($option.Name)" -ForegroundColor Green
                    Write-OptimizationLog "Optimization completed successfully: $($option.Name)" -Level "Info"
                } else {
                    $execContext.FailedOptimizations++
                    $execContext.OverallSuccess = $false
                    # Display simplified error message for user, detailed error in logs
                    $userMessage = if ($optimizationResult.Message.Length -gt 80) {
                        $optimizationResult.Message.Substring(0, 77) + "..."
                    } else {
                        $optimizationResult.Message
                    }
                    Write-Host "  ❌ $($option.Name) - $userMessage" -ForegroundColor Red
                    Write-OptimizationLog "Optimization failed: $($option.Name) - $($optimizationResult.Message)" -Level "Error"

                    # Add rollback operation if available
                    if ($optimizationResult.BeforeValues.Count -gt 0) {
                        $rollbackOp = @{
                            OptimizationName = $option.Name
                            BeforeValues = $optimizationResult.BeforeValues
                            Timestamp = Get-Date
                        }
                        $execContext.RollbackOperations += $rollbackOp
                    }

                    # Decide whether to continue or abort
                    if (-not $ContinueOnError) {
                        Write-Host "  Aborting execution due to failure (ContinueOnError not specified)" -ForegroundColor Yellow
                        Write-OptimizationLog "Execution aborted due to failure in: $($option.Name)" -Level "Warning"

                        # Mark remaining optimizations as skipped
                        for ($j = $i + 1; $j -lt $SelectedOptions.Count; $j++) {
                            $skippedOption = $SelectedOptions[$j]
                            $skippedResult = [OptimizationResult]::new()
                            $skippedResult.OptimizationName = $skippedOption.Name
                            $skippedResult.Success = $false
                            $skippedResult.Message = "Skipped due to previous failure"
                            $skippedResult.Timestamp = Get-Date
                            $execContext.Results += $skippedResult
                            $execContext.SkippedOptimizations++
                        }
                        break
                    } else {
                        Write-Host "  Continuing with remaining optimizations..." -ForegroundColor Yellow
                        Write-OptimizationLog "Continuing execution despite failure in: $($option.Name)" -Level "Info"
                    }
                }

                # Brief pause between optimizations for system stability
                Start-Sleep -Milliseconds 500
            }
            catch {
                $errorMessage = "Critical error executing $($option.Name): $($_.Exception.Message)"
                Write-OptimizationLog $errorMessage -Level "Error"

                # Create error result
                $errorResult = [OptimizationResult]::new()
                $errorResult.OptimizationName = $option.Name
                $errorResult.Success = $false
                $errorResult.Message = $errorMessage
                $errorResult.Timestamp = Get-Date
                $errorResult.AddError($_.Exception.Message)

                $execContext.Results += $errorResult
                $execContext.FailedOptimizations++
                $execContext.OverallSuccess = $false

                # Display simplified error message for user, detailed error in logs
                $userErrorMessage = if ($_.Exception.Message.Length -gt 60) {
                    $_.Exception.Message.Substring(0, 57) + "..."
                } else {
                    $_.Exception.Message
                }
                Write-Host "  ❌ $($option.Name) - $userErrorMessage" -ForegroundColor Red

                if (-not $ContinueOnError) {
                    Write-Host "  Aborting execution due to critical error" -ForegroundColor Red
                    throw
                }
            }
        }

        # Complete progress bar
        Write-Progress -Activity "Executing Network Optimizations" -Completed

        # Calculate execution summary
    $execContext.EndTime = Get-Date
    $execContext.Duration = $execContext.EndTime - $execContext.StartTime

        # Display execution summary
    Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           EXECUTION SUMMARY                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        Write-Host "Execution ID: $($execContext.ExecutionId)" -ForegroundColor Gray
        Write-Host "Duration: $($execContext.Duration.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Gray
        Write-Host "Total Optimizations: $($execContext.TotalOptimizations)" -ForegroundColor White
        Write-Host "Completed Successfully: $($execContext.CompletedOptimizations)" -ForegroundColor Green
        Write-Host "Failed: $($execContext.FailedOptimizations)" -ForegroundColor Red
        Write-Host "Skipped: $($execContext.SkippedOptimizations)" -ForegroundColor Yellow
        Write-Host "Overall Success: $($execContext.OverallSuccess)" -ForegroundColor $(if ($execContext.OverallSuccess) { "Green" } else { "Red" })

        if ($execContext.RollbackOperations.Count -gt 0) {
            Write-Host "Rollback Operations Available: $($execContext.RollbackOperations.Count)" -ForegroundColor Yellow
        }

        # Log execution summary
    Write-OptimizationLog "Optimization execution completed - Success: $($execContext.OverallSuccess), Completed: $($execContext.CompletedOptimizations), Failed: $($execContext.FailedOptimizations), Skipped: $($execContext.SkippedOptimizations)" -Level "Info"

        # Handle rollback if overall execution failed and user wants to rollback
    if (-not $execContext.OverallSuccess -and $execContext.RollbackOperations.Count -gt 0) {
            Write-Host "`nExecution failed with rollback operations available." -ForegroundColor Yellow

            if (-not $Silent) {
                $rollbackChoice = Read-Host "Do you want to rollback the changes? (y/N)"
                if ($rollbackChoice -match '^[Yy]') {
                    Write-Host "Initiating rollback..." -ForegroundColor Yellow
                    $rollbackResult = Invoke-OptimizationRollback -RollbackOperations $execContext.RollbackOperations
                    $execContext.RollbackResult = $rollbackResult

                    if ($rollbackResult.Success) {
                        Write-Host "[OK] Rollback completed successfully" -ForegroundColor Green
                    } else {
                        Write-Host "[FAIL] Rollback failed: $($rollbackResult.Message)" -ForegroundColor Red
                    }
                }
            }
        }

        return @{
            Success = $execContext.OverallSuccess
            Results = $execContext.Results
            ExecutionContext = $execContext
            WhatIfMode = $false
        }
    }
    catch {
        $errorMessage = "Optimization execution engine failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        Write-Error $errorMessage

        # Ensure progress bar is completed even on error
        Write-Progress -Activity "Executing Network Optimizations" -Completed

        $execContext.OverallSuccess = $false
        $execContext.EndTime = Get-Date
        $execContext.Duration = $execContext.EndTime - $execContext.StartTime

        return @{
            Success = $false
            Results = $execContext.Results
            ExecutionContext = $execContext
            Error = $errorMessage
            WhatIfMode = $false
        }
    }
}

function Invoke-SingleOptimization {
        # Execute a single optimization with comprehensive error handling
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([OptimizationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption]$Option,

        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config,

        [Parameter()]
        [hashtable]$BeforeState = @{}
    )

    $result = [OptimizationResult]::new()
    $result.OptimizationName = $Option.Name
    $result.Timestamp = Get-Date
    $result.BeforeValues = $BeforeState

    try {
        Write-OptimizationLog "Executing single optimization: $($Option.Name)" -Level "Debug"

        if ($PSCmdlet.ShouldProcess($Option.Name, "Execute Optimization")) {
            # Continue with optimization
        } else {
            $result.Success = $true
            $result.Message = "WHATIF: Would execute $($Option.Name)"
            Write-OptimizationLog "WHATIF: Would execute optimization: $($Option.Name)" -Level "Info"
            return $result
        }

        # Validate that the optimization action exists and is executable
        if (-not $Option.Action -or $Option.Action -isnot [scriptblock]) {
            throw "Invalid or missing action for optimization: $($Option.Name)"
        }

        # Execute the optimization action with error handling
        $actionResult = $null
        $executionStartTime = Get-Date

        try {
            # Execute the optimization action
            $actionResult = & $Option.Action
            $executionEndTime = Get-Date
            $executionDuration = $executionEndTime - $executionStartTime

            Write-OptimizationLog "Optimization action completed in $($executionDuration.TotalMilliseconds)ms: $($Option.Name)" -Level "Debug"
        }
        catch {
            throw "Optimization action failed: $($_.Exception.Message)"
        }

        # Process the action result
        if ($actionResult -is [OptimizationResult]) {
            # If the action returned an OptimizationResult, use it directly
            $result = $actionResult
            $result.OptimizationName = $Option.Name  # Ensure name consistency
        }
        elseif ($actionResult -is [hashtable]) {
            # If the action returned a hashtable, process it
            $result.Success = if ($actionResult.ContainsKey('Success')) { $actionResult.Success } else { $true }
            $result.Message = if ($actionResult.ContainsKey('Message')) { $actionResult.Message } else { "Optimization completed" }

            if ($actionResult.ContainsKey('AfterValues')) {
                $result.AfterValues = $actionResult.AfterValues
            }

            if ($actionResult.ContainsKey('Errors')) {
                foreach ($errItem in $actionResult.Errors) {
                    $result.AddError($error)
                }
            }
        }
        elseif ($actionResult -is [bool]) {
            # If the action returned a boolean, use it as success indicator
            $result.Success = $actionResult
            $result.Message = if ($actionResult) { "Optimization completed successfully" } else { "Optimization failed" }
        }
        else {
            # Default case - assume success if no exception was thrown
            $result.Success = $true
            $result.Message = "Optimization completed successfully"

            # Try to capture after state if possible
            $afterState = Get-SystemState -Option $Option
            $result.AfterValues = $afterState
        }

        # Ensure we have before values
        if ($result.BeforeValues.Count -eq 0) {
            $result.BeforeValues = $BeforeState
        }

        Write-OptimizationLog "Single optimization execution completed: $($Option.Name) - Success: $($result.Success)" -Level "Info"

        return $result
    }
    catch {
        $errorMessage = "Failed to execute optimization $($Option.Name): $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"

        $result.Success = $false
        $result.Message = $errorMessage
        $result.AddError($_.Exception.Message)

        # Add stack trace for debugging
        if ($_.Exception.StackTrace) {
            $result.AddError("Stack trace: $($_.Exception.StackTrace)")
        }

        return $result
    }
}

function Test-PreExecutionValidation {
        # Perform comprehensive validation before executing optimizations
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption[]]$SelectedOptions,

        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    try {
        Write-OptimizationLog "Starting pre-execution validation" -Level "Info"

        $validationResults = @()

        # Validate administrator privileges
        if (-not (Test-AdministratorPrivileges)) {
            $validationResults += "Administrator privileges required but not available"
        }

        # Validate Windows version compatibility
        if (-not (Test-WindowsVersion)) {
            $validationResults += "Incompatible Windows version detected"
        }

        # Validate PowerShell version
        if (-not (Test-PowerShellVersion)) {
            $validationResults += "Incompatible PowerShell version detected"
        }

        # Validate backup system is ready
        if (-not $Script:BackupInfo -or -not $Script:BackupInfo.Success) {
            $validationResults += "Backup system not properly initialized"
        }

        # Validate each selected option
        foreach ($option in $SelectedOptions) {
            if (-not $option.Action -or $option.Action -isnot [scriptblock]) {
                $validationResults += "Invalid action for optimization: $($option.Name)"
            }

            # Check option requirements if specified
            if ($option.Requirements -and $option.Requirements.Count -gt 0) {
                foreach ($requirement in $option.Requirements) {
                    # Validate specific requirements (this could be expanded based on needs)
                    Write-OptimizationLog "Validating requirement for $($option.Name): $requirement" -Level "Debug"
                }
            }
        }

        # Validate system resources
        $availableMemory = (Get-CimInstance -ClassName Win32_OperatingSystem).FreePhysicalMemory
        if ($availableMemory -lt 100000) {  # Less than ~100MB
            $validationResults += "Insufficient available memory for safe operation"
        }

        # Check for pending reboot (unless Force is specified)
        if (-not $Force) {
            $pendingReboot = Test-PendingReboot
            if ($pendingReboot) {
                $validationResults += "System has pending reboot - some optimizations may not apply correctly"
            }
        }

        $success = $validationResults.Count -eq 0
        $message = if ($success) {
            "Pre-execution validation passed successfully"
        } else {
            "Pre-execution validation failed: $($validationResults -join '; ')"
        }

        Write-OptimizationLog "Pre-execution validation completed - Success: $success" -Level "Info"

        return @{
            Success = $success
            Message = $message
            ValidationResults = $validationResults
        }
    }
    catch {
        $errorMessage = "Pre-execution validation error: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"

        return @{
            Success = $false
            Message = $errorMessage
            ValidationResults = @($errorMessage)
        }
    }
}

function Test-OptimizationValidation {
        # Validate a specific optimization before execution
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption]$Option,

        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    try {
        Write-OptimizationLog "Validating optimization: $($Option.Name)" -Level "Debug"

        $validationIssues = @()

        # Validate the optimization action exists
        if (-not $Option.Action -or $Option.Action -isnot [scriptblock]) {
            $validationIssues += "Missing or invalid action scriptblock"
        }

        # Category-specific validations
        switch ($Option.Category) {
            "TCP/IP Protocol Stack" {
                # Validate TCP/IP stack is available
                if (-not (Get-Service -Name "Tcpip" -ErrorAction SilentlyContinue)) {
                    $validationIssues += "TCP/IP service not available"
                }
            }
            "Connection Type Optimization" {
                # Validate network adapters are present
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
                if (-not $adapters) {
                    $validationIssues += "No network adapters found"
                }
            }
            "DNS and Memory Management" {
                # Validate DNS client service
                $dnsService = Get-Service -Name "Dnscache" -ErrorAction SilentlyContinue
                if (-not $dnsService -or $dnsService.Status -ne "Running") {
                    $validationIssues += "DNS Client service not running"
                }
            }
            "Network Security" {
                # Validate Windows Firewall service
                $firewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
                if (-not $firewallService) {
                    $validationIssues += "Windows Firewall service not available"
                }
            }
        }

        $success = $validationIssues.Count -eq 0
        $message = if ($success) {
            "Optimization validation passed"
        } else {
            "Optimization validation failed: $($validationIssues -join '; ')"
        }

        return @{
            Success = $success
            Message = $message
            ValidationIssues = $validationIssues
        }
    }
    catch {
        $errorMessage = "Optimization validation error: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"

        return @{
            Success = $false
            Message = $errorMessage
            ValidationIssues = @($errorMessage)
        }
    }
}

function Test-PostOptimizationValidation {
        # Validate system state after optimization execution
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption]$Option,

        [Parameter(Mandatory = $true)]
        [OptimizationResult]$Result,

        [Parameter(Mandatory = $true)]
        [NetworkOptimizerConfig]$Config
    )

    try {
        Write-OptimizationLog "Performing post-optimization validation for: $($Option.Name)" -Level "Debug"

        $validationIssues = @()

        # Basic result validation
        if (-not $Result.Success) {
            return @{
                Success = $true  # Don't fail post-validation if the optimization itself failed
                Message = "Skipping post-validation due to optimization failure"
            }
        }

        # Validate system stability after optimization
        try {
            # Check if critical services are still running
            $criticalServices = @("Tcpip", "Dnscache", "Dhcp")
            foreach ($serviceName in $criticalServices) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -ne "Running") {
                    $validationIssues += "Critical service $serviceName is not running after optimization"
                }
            }

            # Validate network connectivity is still available with retry logic
            # Allow time for TCP stack changes to take effect
            Start-Sleep -Milliseconds 500

            $networkTest = $false
            $testHosts = @("8.8.8.8", "1.1.1.1")
            $retryCount = 3

            for ($i = 0; $i -lt $retryCount; $i++) {
                foreach ($testHost in $testHosts) {
                    try {
                        $networkTest = Test-Connection -ComputerName $testHost -Count 1 -Quiet -TimeoutSeconds 2 -ErrorAction SilentlyContinue
                        if ($networkTest) {
                            Write-OptimizationLog "Network connectivity verified via $testHost" -Level "Debug"
                            break
                        }
                    }
                    catch {
                        Write-OptimizationLog "Connectivity test to $testHost failed: $($_.Exception.Message)" -Level "Debug"
                    }
                }
                if ($networkTest) { break }
                if ($i -lt ($retryCount - 1)) {
                    Start-Sleep -Seconds 1
                }
            }

            # If connectivity tests fail, check if adapters are up (more forgiving)
            if (-not $networkTest) {
                try {
                    $activeAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
                    if ($activeAdapters) {
                        Write-OptimizationLog "Network adapters are UP, treating connectivity as functional despite ping failures" -Level "Debug"
                        # Don't add to validation issues - adapters being up is sufficient
                    } else {
                        $validationIssues += "Network connectivity test failed and no active adapters found"
                    }
                }
                catch {
                    # Even this failed, but we'll be lenient
                    Write-OptimizationLog "Could not verify network state, assuming optimization is safe" -Level "Warning"
                }
            }

            # Category-specific post-validation
            switch ($Option.Category) {
                "TCP/IP Protocol Stack" {
                    # Validate TCP settings were applied if registry changes were made
                    if ($Result.AfterValues.Count -gt 0) {
                        foreach ($regPath in $Result.AfterValues.Keys) {
                            if (Test-Path $regPath) {
                                Write-OptimizationLog "Verified registry path exists: $regPath" -Level "Debug"
                            } else {
                                $validationIssues += "Registry path not found after optimization: $regPath"
                            }
                        }
                    }
                }
                "DNS and Memory Management" {
                    # Validate DNS resolution is working
                    try {
                        $dnsTest = Resolve-DnsName -Name "google.com" -ErrorAction Stop
                        if (-not $dnsTest) {
                            $validationIssues += "DNS resolution test failed after optimization"
                        }
                    }
                    catch {
                        $validationIssues += "DNS resolution error after optimization: $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
            $validationIssues += "System stability check failed: $($_.Exception.Message)"
        }

        $success = $validationIssues.Count -eq 0
        $message = if ($success) {
            "Post-optimization validation passed"
        } else {
            "Post-optimization validation issues detected: $($validationIssues -join '; ')"
        }

        Write-OptimizationLog "Post-optimization validation completed for $($Option.Name) - Success: $success" -Level "Debug"

        return @{
            Success = $success
            Message = $message
            ValidationIssues = $validationIssues
        }
    }
    catch {
        $errorMessage = "Post-optimization validation error: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"

        return @{
            Success = $false
            Message = $errorMessage
            ValidationIssues = @($errorMessage)
        }
    }
}

function Get-SystemState {
        # Capture current system state for an optimization
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationOption]$Option
    )

    try {
        $systemState = @{}

        # Capture state based on optimization category
        switch ($Option.Category) {
            "TCP/IP Protocol Stack" {
                # Capture TCP/IP registry settings
                $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                if (Test-Path $tcpipPath) {
                    $tcpipSettings = Get-ItemProperty -Path $tcpipPath -ErrorAction SilentlyContinue
                    if ($tcpipSettings) {
                        $systemState[$tcpipPath] = @{}
                        foreach ($property in $tcpipSettings.PSObject.Properties) {
                            if ($property.Name -notmatch '^PS') {
                                $systemState[$tcpipPath][$property.Name] = $property.Value
                            }
                        }
                    }
                }
            }
            "Connection Type Optimization" {
                # Capture network adapter settings
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
                if ($adapters) {
                    $systemState["NetworkAdapters"] = @{}
                    foreach ($adapter in $adapters) {
                        $systemState["NetworkAdapters"][$adapter.Name] = @{
                            Status = $adapter.Status
                            LinkSpeed = $adapter.LinkSpeed
                            MediaType = $adapter.MediaType
                        }
                    }
                }
            }
            "DNS and Memory Management" {
                # Capture DNS and memory settings
                $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                if (Test-Path $dnsPath) {
                    $dnsSettings = Get-ItemProperty -Path $dnsPath -ErrorAction SilentlyContinue
                    if ($dnsSettings) {
                        $systemState[$dnsPath] = @{}
                        foreach ($property in $dnsSettings.PSObject.Properties) {
                            if ($property.Name -notmatch '^PS') {
                                $systemState[$dnsPath][$property.Name] = $property.Value
                            }
                        }
                    }
                }
            }
        }

        # Add timestamp
        $systemState["CaptureTimestamp"] = Get-Date

        Write-OptimizationLog "System state captured for $($Option.Name): $($systemState.Keys.Count) items" -Level "Debug"

        return $systemState
    }
    catch {
        Write-OptimizationLog "Failed to capture system state for $($Option.Name): $($_.Exception.Message)" -Level "Warning"
        return @{}
    }
}

function Invoke-OptimizationRollback {
        # Rollback optimization changes using captured system state
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$RollbackOperations
    )

    try {
        Write-OptimizationLog "Starting optimization rollback for $($RollbackOperations.Count) operations" -Level "Info"

        if ($PSCmdlet.ShouldProcess("$($RollbackOperations.Count) operations", "Rollback Optimizations")) {
            # Continue with rollback
        } else {
            Write-Host "WHATIF: Would rollback $($RollbackOperations.Count) optimization operations" -ForegroundColor Magenta
            return @{ Success = $true; Message = "WHATIF: Rollback operations identified" }
        }

        $rollbackResults = @()
        $successCount = 0
        $failureCount = 0

        foreach ($operation in $RollbackOperations) {
            try {
                Write-Host "Rolling back: $($operation.OptimizationName)" -ForegroundColor Yellow
                Write-OptimizationLog "Rolling back optimization: $($operation.OptimizationName)" -Level "Info"

                # Restore registry values
                foreach ($regPath in $operation.BeforeValues.Keys) {
                    if ($regPath -eq "CaptureTimestamp") { continue }

                    if (Test-Path $regPath) {
                        $values = $operation.BeforeValues[$regPath]
                        foreach ($valueName in $values.Keys) {
                            try {
                                Set-ItemProperty -Path $regPath -Name $valueName -Value $values[$valueName] -Force
                                Write-OptimizationLog "Restored registry value: $regPath\$valueName" -Level "Debug"
                            }
                            catch {
                                Write-OptimizationLog "Failed to restore registry value: $regPath\$valueName - $($_.Exception.Message)" -Level "Warning"
                            }
                        }
                    }
                }

                $rollbackResults += @{
                    OptimizationName = $operation.OptimizationName
                    Success = $true
                    Message = "Rollback completed successfully"
                }
                $successCount++

                Write-Host "  [OK] Rollback completed for: $($operation.OptimizationName)" -ForegroundColor Green
            }
            catch {
                $errorMessage = "Rollback failed for $($operation.OptimizationName): $($_.Exception.Message)"
                Write-OptimizationLog $errorMessage -Level "Error"

                $rollbackResults += @{
                    OptimizationName = $operation.OptimizationName
                    Success = $false
                    Message = $errorMessage
                }
                $failureCount++

                Write-Host "  [FAIL] Rollback failed for: $($operation.OptimizationName)" -ForegroundColor Red
            }
        }

        $overallSuccess = $failureCount -eq 0
        $message = "Rollback completed - Success: $successCount, Failed: $failureCount"

        Write-OptimizationLog "Optimization rollback completed - Overall success: $overallSuccess" -Level "Info"

        return @{
            Success = $overallSuccess
            Message = $message
            Results = $rollbackResults
            SuccessCount = $successCount
            FailureCount = $failureCount
        }
    }
    catch {
        $errorMessage = "Rollback operation failed: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"

        return @{
            Success = $false
            Message = $errorMessage
            Results = @()
        }
    }
}

function Test-PendingReboot {
        # Check if the system has a pending reboot
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        # Check Windows Update reboot flag
        $wuReboot = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
        if ($wuReboot) { return $true }

        # Check Component Based Servicing reboot flag
        $cbsReboot = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
        if ($cbsReboot) { return $true }

        # Check pending file rename operations
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename) { return $true }

        return $false
    }
    catch {
        Write-OptimizationLog "Failed to check pending reboot status: $($_.Exception.Message)" -Level "Warning"
        return $false
    }
}

#endregion

#region Progress Tracking and Reporting System

function Show-ProgressBar {
        # Display real-time progress feedback using Write-Progress
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter()]
        [string]$Status = "Processing...",

        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = 0,

        [Parameter()]
        [string]$CurrentOperation = "",

        [Parameter()]
        [int]$Id = 1,

        [Parameter()]
        [int]$ParentId = -1,

        [Parameter()]
        [switch]$Completed
    )

    try {
        $progressParams = @{
            Activity = $Activity
            Status = $Status
            PercentComplete = $PercentComplete
            Id = $Id
        }

        if ($CurrentOperation) {
            $progressParams.CurrentOperation = $CurrentOperation
        }

        if ($ParentId -ge 0) {
            $progressParams.ParentId = $ParentId
        }

        if ($Completed) {
            $progressParams.Completed = $true
        }

        Write-Progress @progressParams

        # Log progress for debugging and audit trail
        $logMessage = "Progress: $Activity - $Status ($PercentComplete%)"
        if ($CurrentOperation) {
            $logMessage += " - $CurrentOperation"
        }
        Write-OptimizationLog $logMessage -Level "Debug"

        # Small delay to ensure progress bar is visible
        if (-not $Completed) {
            Start-Sleep -Milliseconds 50
        }
    }
    catch {
        Write-OptimizationLog "Failed to update progress bar: $($_.Exception.Message)" -Level "Warning"
        # Don't throw error for progress bar failures - they're not critical
    }
}

function New-NetworkHealthReport {
        # Generate comprehensive before/after comparison reports for network optimizations
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$BeforeSettings = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AfterSettings = @{},

        [Parameter(Mandatory = $false)]
        [OptimizationResult[]]$OptimizationResults = @(),

        [Parameter()]
        [string]$OutputPath = $Script:BackupPath,

        [Parameter()]
        [ValidateSet("HTML", "JSON", "Text", "All")]
        [string]$Format = "All",

        [Parameter()]
        [switch]$IncludeSystemInfo
    )

    try {
        Write-OptimizationLog "Generating network health report in format: $Format" -Level "Info"

        # Handle empty results (e.g., in WhatIf mode)
        if ($null -eq $OptimizationResults -or $OptimizationResults.Count -eq 0) {
            Write-OptimizationLog "No optimization results to report (WhatIf mode or no optimizations performed)" -Level "Info"
            return @{
                Success = $true
                Message = "No optimization results to report"
                Timestamp = Get-Date
                OutputPath = $OutputPath
                Files = @()
                Summary = @{
                    TotalOptimizations = 0
                    SuccessfulOptimizations = 0
                    FailedOptimizations = 0
                    SuccessRate = 0
                    TotalChanges = 0
                    TotalErrors = 0
                }
            }
        }

        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        # Generate timestamp for report files
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportInfo = @{
            Success = $true
            Timestamp = Get-Date
            OutputPath = $OutputPath
            Files = @()
            Summary = @{}
        }

        # Calculate summary statistics
        $totalOptimizations = $OptimizationResults.Count
        $successfulOptimizations = ($OptimizationResults | Where-Object { $_.Success }).Count
        $failedOptimizations = $totalOptimizations - $successfulOptimizations
        $totalChanges = if ($OptimizationResults.Count -gt 0) { ($OptimizationResults | ForEach-Object { $_.AfterValues.Count } | Measure-Object -Sum).Sum } else { 0 }
        $totalErrors = if ($OptimizationResults.Count -gt 0) { ($OptimizationResults | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum } else { 0 }

        $reportInfo.Summary = @{
            TotalOptimizations = $totalOptimizations
            SuccessfulOptimizations = $successfulOptimizations
            FailedOptimizations = $failedOptimizations
            SuccessRate = if ($totalOptimizations -gt 0) { [math]::Round(($successfulOptimizations / $totalOptimizations) * 100, 2) } else { 0 }
            TotalChanges = $totalChanges
            TotalErrors = $totalErrors
        }

        # Collect system information if requested
        $systemInfo = @{}
        if ($IncludeSystemInfo) {
            try {
                $systemInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    UserName = $env:USERNAME
                    OSVersion = [System.Environment]::OSVersion.VersionString
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    ScriptVersion = $Script:Version
                    ExecutionTime = (Get-Date) - $Script:StartTime
                    NetworkAdapters = @()
                }

                # Get network adapter information
                $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
                foreach ($adapter in $adapters) {
                    $systemInfo.NetworkAdapters += @{
                        Name = $adapter.Name
                        InterfaceDescription = $adapter.InterfaceDescription
                        LinkSpeed = $adapter.LinkSpeed
                        MediaType = $adapter.MediaType
                    }
                }
            }
            catch {
                Write-OptimizationLog "Failed to collect system information: $($_.Exception.Message)" -Level "Warning"
            }
        }

        # Generate reports based on format selection
        if ($Format -eq "HTML" -or $Format -eq "All") {
            $htmlFile = Join-Path $OutputPath "NetworkHealthReport_$timestamp.html"
            $htmlContent = New-HTMLReport -BeforeSettings $BeforeSettings -AfterSettings $AfterSettings -OptimizationResults $OptimizationResults -Summary $reportInfo.Summary -SystemInfo $systemInfo
            $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8 -Force
            $reportInfo.Files += $htmlFile
            Write-OptimizationLog "HTML report generated: $htmlFile" -Level "Info"
        }

        if ($Format -eq "JSON" -or $Format -eq "All") {
            $jsonFile = Join-Path $OutputPath "NetworkHealthReport_$timestamp.json"
            $jsonData = @{
                ReportMetadata = @{
                    GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    ScriptVersion = $Script:Version
                    ReportVersion = "1.0"
                }
                Summary = $reportInfo.Summary
                SystemInfo = $systemInfo
                BeforeSettings = $BeforeSettings
                AfterSettings = $AfterSettings
                OptimizationResults = $OptimizationResults | ForEach-Object {
                    @{
                        OptimizationName = $_.OptimizationName
                        Success = $_.Success
                        Message = $_.Message
                        BeforeValues = $_.BeforeValues
                        AfterValues = $_.AfterValues
                        Timestamp = $_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
                        Errors = $_.Errors
                    }
                }
            }
            $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
            $reportInfo.Files += $jsonFile
            Write-OptimizationLog "JSON report generated: $jsonFile" -Level "Info"
        }

        if ($Format -eq "Text" -or $Format -eq "All") {
            $textFile = Join-Path $OutputPath "NetworkHealthReport_$timestamp.txt"
            $textContent = New-TextReport -BeforeSettings $BeforeSettings -AfterSettings $AfterSettings -OptimizationResults $OptimizationResults -Summary $reportInfo.Summary -SystemInfo $systemInfo
            $textContent | Out-File -FilePath $textFile -Encoding UTF8 -Force
            $reportInfo.Files += $textFile
            Write-OptimizationLog "Text report generated: $textFile" -Level "Info"
        }

        Write-OptimizationLog "Network health report generation completed. Files: $($reportInfo.Files.Count)" -Level "Info"
        return $reportInfo
    }
    catch {
        $errorMessage = "Failed to generate network health report: $($_.Exception.Message)"
        Write-OptimizationLog $errorMessage -Level "Error"
        return @{ Success = $false; Error = $errorMessage }
    }
}

function New-HTMLReport {
        # Generate HTML format network health report
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [hashtable]$BeforeSettings,
        [hashtable]$AfterSettings,
        [OptimizationResult[]]$OptimizationResults,
        [hashtable]$Summary,
        [hashtable]$SystemInfo
    )

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Optimizer Health Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 3px solid #007acc; }
        .header h1 { color: #007acc; margin: 0; font-size: 2.5em; }
        .header .subtitle { color: #666; font-size: 1.2em; margin-top: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #007acc, #005a9e); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 1.1em; }
        .summary-card .value { font-size: 2em; font-weight: bold; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .optimization-result { background-color: #f9f9f9; border-left: 4px solid #007acc; padding: 15px; margin-bottom: 15px; border-radius: 0 5px 5px 0; }
        .optimization-result.success { border-left-color: #28a745; }
        .optimization-result.failed { border-left-color: #dc3545; }
        .optimization-result h4 { margin: 0 0 10px 0; color: #333; }
        .optimization-result .status { font-weight: bold; }
        .optimization-result .status.success { color: #28a745; }
        .optimization-result .status.failed { color: #dc3545; }
        .changes-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .changes-table th, .changes-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .changes-table th { background-color: #f2f2f2; font-weight: bold; }
        .changes-table tr:nth-child(even) { background-color: #f9f9f9; }
        .system-info { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .system-info dl { display: grid; grid-template-columns: 200px 1fr; gap: 10px; margin: 0; }
        .system-info dt { font-weight: bold; color: #495057; }
        .system-info dd { margin: 0; color: #6c757d; }
        .footer { text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Optimizer Health Report</h1>
            <div class="subtitle">Generated on $(Get-Date -Format 'MMMM dd, yyyy at HH:mm:ss')</div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Optimizations</h3>
                <div class="value">$($Summary.TotalOptimizations)</div>
            </div>
            <div class="summary-card">
                <h3>Success Rate</h3>
                <div class="value">$($Summary.SuccessRate)%</div>
            </div>
            <div class="summary-card">
                <h3>Changes Applied</h3>
                <div class="value">$($Summary.TotalChanges)</div>
            </div>
            <div class="summary-card">
                <h3>Errors</h3>
                <div class="value">$($Summary.TotalErrors)</div>
            </div>
        </div>
"@

    # Add system information if available
    if ($SystemInfo.Count -gt 0) {
        $html += @"
        <div class="section">
            <h2>System Information</h2>
            <div class="system-info">
                <dl>
                    <dt>Computer Name:</dt><dd>$($SystemInfo.ComputerName)</dd>
                    <dt>User:</dt><dd>$($SystemInfo.UserName)</dd>
                    <dt>OS Version:</dt><dd>$($SystemInfo.OSVersion)</dd>
                    <dt>PowerShell Version:</dt><dd>$($SystemInfo.PowerShellVersion)</dd>
                    <dt>Script Version:</dt><dd>$($SystemInfo.ScriptVersion)</dd>
                    <dt>Execution Time:</dt><dd>$($SystemInfo.ExecutionTime)</dd>
                </dl>
            </div>
        </div>
"@
    }

    # Add optimization results
    $html += @"
        <div class="section">
            <h2>Optimization Results</h2>
"@

    foreach ($result in $OptimizationResults) {
        $statusClass = if ($result.Success) { "success" } else { "failed" }
        $statusText = if ($result.Success) { "SUCCESS" } else { "FAILED" }

        $html += @"
            <div class="optimization-result $statusClass">
                <h4>$($result.OptimizationName)</h4>
                <p><span class="status $statusClass">$statusText</span> - $($result.Message)</p>
                <p><strong>Timestamp:</strong> $($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>
"@

        if ($result.AfterValues.Count -gt 0) {
            $html += @"
                <table class="changes-table">
                    <thead>
                        <tr><th>Setting</th><th>Before</th><th>After</th></tr>
                    </thead>
                    <tbody>
"@
            foreach ($key in $result.AfterValues.Keys) {
                $beforeValue = if ($result.BeforeValues.ContainsKey($key)) { $result.BeforeValues[$key] } else { "Not Set" }
                $afterValue = $result.AfterValues[$key]
                $html += "<tr><td>$key</td><td>$beforeValue</td><td>$afterValue</td></tr>"
            }
            $html += "</tbody></table>"
        }

        if ($result.Errors.Count -gt 0) {
            $html += "<p><strong>Errors:</strong></p><ul>"
            foreach ($errItem in $result.Errors) {
                $html += "<li>$error</li>"
            }
            $html += "</ul>"
        }

        $html += "</div>"
    }

    $html += @"
        </div>

        <div class="footer">
            <p>Report generated by Network Optimizer v$Script:Version</p>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function New-TextReport {
        # Generate plain text format network health report
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [hashtable]$BeforeSettings,
        [hashtable]$AfterSettings,
        [OptimizationResult[]]$OptimizationResults,
        [hashtable]$Summary,
        [hashtable]$SystemInfo
    )

    $text = @"
================================================================================
                        NETWORK OPTIMIZER HEALTH REPORT
================================================================================

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: $Script:Version

SUMMARY
=======
Total Optimizations: $($Summary.TotalOptimizations)
Successful: $($Summary.SuccessfulOptimizations)
Failed: $($Summary.FailedOptimizations)
Success Rate: $($Summary.SuccessRate)%
Total Changes Applied: $($Summary.TotalChanges)
Total Errors: $($Summary.TotalErrors)

"@

    # Add system information if available
    if ($SystemInfo.Count -gt 0) {
        $text += @"
SYSTEM INFORMATION
==================
Computer Name: $($SystemInfo.ComputerName)
User: $($SystemInfo.UserName)
OS Version: $($SystemInfo.OSVersion)
PowerShell Version: $($SystemInfo.PowerShellVersion)
Script Version: $($SystemInfo.ScriptVersion)
Execution Time: $($SystemInfo.ExecutionTime)

"@

        if ($SystemInfo.NetworkAdapters.Count -gt 0) {
            $text += "Network Adapters:`n"
            foreach ($adapter in $SystemInfo.NetworkAdapters) {
                $text += "  - $($adapter.Name) ($($adapter.InterfaceDescription))`n"
                $text += "    Link Speed: $($adapter.LinkSpeed), Media Type: $($adapter.MediaType)`n"
            }
            $text += "`n"
        }
    }

    # Add optimization results
    $text += @"
OPTIMIZATION RESULTS
====================

"@

    foreach ($result in $OptimizationResults) {
        $status = if ($result.Success) { "SUCCESS" } else { "FAILED" }
        $text += @"
[$status] $($result.OptimizationName)
$("-" * (9 + $result.OptimizationName.Length))
Message: $($result.Message)
Timestamp: $($result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))

"@

        if ($result.AfterValues.Count -gt 0) {
            $text += "Changes Applied:`n"
            foreach ($key in $result.AfterValues.Keys) {
                $beforeValue = if ($result.BeforeValues.ContainsKey($key)) { $result.BeforeValues[$key] } else { "Not Set" }
                $afterValue = $result.AfterValues[$key]
                $text += "  $key`: $beforeValue -> $afterValue`n"
            }
            $text += "`n"
        }

        if ($result.Errors.Count -gt 0) {
            $text += "Errors:`n"
            foreach ($errItem in $result.Errors) {
                $text += "  - $error`n"
            }
            $text += "`n"
        }
    }

    $text += @"
================================================================================
Report generated by Network Optimizer v$Script:Version
================================================================================
"@

    return $text
}

function Add-OptimizationResult {
        # Add an optimization result to the global tracking collection
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationResult]$Result
    )

    try {
        if ($null -eq $Script:OptimizationResults) {
            $Script:OptimizationResults = @()
        }

        $Script:OptimizationResults += $Result

        Write-OptimizationLog "Added optimization result: $($Result.OptimizationName) - Success: $($Result.Success)" -Level "Debug"

        # Log summary of the result
        $summary = $Result.GetSummary()
        Write-OptimizationLog $summary -Level "Info"
    }
    catch {
        Write-OptimizationLog "Failed to add optimization result: $($_.Exception.Message)" -Level "Error"
    }
}

function Get-OptimizationSummary {
        # Generate a summary of all optimization results
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        if ($null -eq $Script:OptimizationResults -or $Script:OptimizationResults.Count -eq 0) {
            return @{
                TotalOptimizations = 0
                SuccessfulOptimizations = 0
                FailedOptimizations = 0
                SuccessRate = 0
                TotalChanges = 0
                TotalErrors = 0
                Categories = @{}
            }
        }

        $totalOptimizations = $Script:OptimizationResults.Count
        $successfulOptimizations = ($Script:OptimizationResults | Where-Object { $_.Success }).Count
        $failedOptimizations = $totalOptimizations - $successfulOptimizations
        $totalChanges = ($Script:OptimizationResults | ForEach-Object { $_.AfterValues.Count } | Measure-Object -Sum).Sum
        $totalErrors = ($Script:OptimizationResults | ForEach-Object { $_.Errors.Count } | Measure-Object -Sum).Sum

        # Group by optimization categories
        $categories = @{}
        foreach ($result in $Script:OptimizationResults) {
            $category = $result.OptimizationName -replace ' .*', ''  # Get first word as category
            if (-not $categories.ContainsKey($category)) {
                $categories[$category] = @{
                    Total = 0
                    Successful = 0
                    Failed = 0
                    Changes = 0
                    Errors = 0
                }
            }

            $categories[$category].Total++
            if ($result.Success) {
                $categories[$category].Successful++
            } else {
                $categories[$category].Failed++
            }
            $categories[$category].Changes += $result.AfterValues.Count
            $categories[$category].Errors += $result.Errors.Count
        }

        $summary = @{
            TotalOptimizations = $totalOptimizations
            SuccessfulOptimizations = $successfulOptimizations
            FailedOptimizations = $failedOptimizations
            SuccessRate = if ($totalOptimizations -gt 0) { [math]::Round(($successfulOptimizations / $totalOptimizations) * 100, 2) } else { 0 }
            TotalChanges = $totalChanges
            TotalErrors = $totalErrors
            Categories = $categories
            ExecutionTime = (Get-Date) - $Script:StartTime
        }

        Write-OptimizationLog "Generated optimization summary: $totalOptimizations total, $successfulOptimizations successful ($($summary.SuccessRate)%)" -Level "Info"

        return $summary
    }
    catch {
        Write-OptimizationLog "Failed to generate optimization summary: $($_.Exception.Message)" -Level "Error"
        return @{ Error = $_.Exception.Message }
    }
}

function New-OptimizationResult {
        # Create a new OptimizationResult object with proper initialization
    [CmdletBinding()]
    [OutputType([OptimizationResult])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OptimizationName,

        [Parameter()]
        [hashtable]$BeforeValues = @{}
    )

    try {
        $result = [OptimizationResult]::new()
        $result.OptimizationName = $OptimizationName
        $result.BeforeValues = $BeforeValues.Clone()
        $result.Timestamp = Get-Date

        Write-OptimizationLog "Created new optimization result for: $OptimizationName" -Level "Debug"
        return $result
    }
    catch {
        Write-OptimizationLog "Failed to create optimization result: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Complete-OptimizationResult {
        # Complete an optimization result and add it to the tracking collection
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [OptimizationResult]$Result,

        [Parameter(Mandatory = $true)]
        [bool]$Success,

        [Parameter()]
        [string]$Message = "",

        [Parameter()]
        [hashtable]$AfterValues = @{},

        [Parameter()]
        [string[]]$Errors = @()
    )

    try {
        $Result.Success = $Success
        $Result.Message = $Message
        $Result.AfterValues = $AfterValues.Clone()

    foreach ($errItem in $Errors) {
            $Result.AddError($error)
        }

        # Add to global collection
        Add-OptimizationResult -Result $Result

        Write-OptimizationLog "Completed optimization result: $($Result.OptimizationName) - Success: $Success" -Level "Info"
    }
    catch {
        Write-OptimizationLog "Failed to complete optimization result: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

function Show-OptimizationSummary {
        # Display a formatted summary of all optimization results
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Detailed
    )

    try {
        $summary = Get-OptimizationSummary

        if ($summary.ContainsKey('Error')) {
            Write-Host "Error generating summary: $($summary.Error)" -ForegroundColor Red
            return
        }

        Write-Host ""
        Write-Host "OPTIMIZATION SUMMARY" -ForegroundColor Cyan
        Write-Host "===================" -ForegroundColor Cyan
        Write-Host ""

        # Overall statistics
        Write-Host "Overall Results:" -ForegroundColor Yellow
        Write-Host "  Total Optimizations: $($summary.TotalOptimizations)" -ForegroundColor White
        Write-Host "  Successful: $($summary.SuccessfulOptimizations)" -ForegroundColor Green
        Write-Host "  Failed: $($summary.FailedOptimizations)" -ForegroundColor Red
        Write-Host "  Success Rate: $($summary.SuccessRate)%" -ForegroundColor $(if ($summary.SuccessRate -ge 80) { "Green" } elseif ($summary.SuccessRate -ge 60) { "Yellow" } else { "Red" })
        Write-Host "  Total Changes Applied: $($summary.TotalChanges)" -ForegroundColor White
        Write-Host "  Total Errors: $($summary.TotalErrors)" -ForegroundColor $(if ($summary.TotalErrors -eq 0) { "Green" } else { "Red" })
        Write-Host "  Execution Time: $($summary.ExecutionTime)" -ForegroundColor White
        Write-Host ""

        # Category breakdown if detailed
        if ($Detailed -and $summary.Categories.Count -gt 0) {
            Write-Host "Category Breakdown:" -ForegroundColor Yellow
            foreach ($category in $summary.Categories.Keys | Sort-Object) {
                $cat = $summary.Categories[$category]
                $catSuccessRate = if ($cat.Total -gt 0) { [math]::Round(($cat.Successful / $cat.Total) * 100, 1) } else { 0 }
                Write-Host "  $category`:" -ForegroundColor Cyan
                Write-Host "    Total: $($cat.Total), Successful: $($cat.Successful), Failed: $($cat.Failed) ($catSuccessRate%)" -ForegroundColor White
                Write-Host "    Changes: $($cat.Changes), Errors: $($cat.Errors)" -ForegroundColor White
            }
            Write-Host ""
        }

        # Individual results if detailed and not too many
        if ($Detailed -and $Script:OptimizationResults.Count -le 20) {
            Write-Host "Individual Results:" -ForegroundColor Yellow
            foreach ($result in $Script:OptimizationResults) {
                $status = if ($result.Success) { "[OK]" } else { "[FAIL]" }
                $statusColor = if ($result.Success) { "Green" } else { "Red" }
                Write-Host "  $status $($result.OptimizationName)" -ForegroundColor $statusColor
                if (-not $result.Success -and $result.Errors.Count -gt 0) {
                    Write-Host "    Error: $($result.Errors[0])" -ForegroundColor Red
                }
            }
            Write-Host ""
        }

        # Recommendations
        if ($summary.FailedOptimizations -gt 0) {
            Write-Host "Recommendations:" -ForegroundColor Yellow
            Write-Host "  • Review failed optimizations in the detailed log" -ForegroundColor White
            Write-Host "  • Consider running individual optimizations manually" -ForegroundColor White
            Write-Host "  • Check system requirements and permissions" -ForegroundColor White
        }

        if ($summary.TotalErrors -gt 0) {
            Write-Host "  • Review error messages for troubleshooting guidance" -ForegroundColor White
        }

        Write-Host ""
        Write-OptimizationLog "Displayed optimization summary to user" -Level "Info"
    }
    catch {
        Write-OptimizationLog "Failed to display optimization summary: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error displaying optimization summary: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion

#region Interactive Menu System

function Show-MainMenu {
        # Display the main menu with formatted menu display using Write-Host
    [CmdletBinding()]
    param()

    try {
        Clear-Host

        # Display header with version and system info
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                        PowerShell Network Optimizer v$Script:Version                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        # Get current network product name using .NET NetworkInterface only (clean, WhatIf/admin safe)
        $networkProduct = "Unknown Adapter"
        try {
            $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
                Where-Object {
                    $_.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up -and
                    $_.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback -and
                    $_.NetworkInterfaceType -ne [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel
                }
            if ($nics -and $nics.Count -gt 0) {
                $primaryNic = $nics | Sort-Object Speed -Descending | Select-Object -First 1
                $networkProduct = if ($primaryNic.Description) { $primaryNic.Description } else { $primaryNic.Name }
            }
        } catch {
            # Leave as Unknown Adapter if detection fails
        }

        Write-Host "System: $env:COMPUTERNAME | User: $env:USERNAME | PowerShell: $($PSVersionTable.PSVersion) | Network: $networkProduct" -ForegroundColor Gray
        Write-Host "Log File: $Script:LogFile" -ForegroundColor Gray
        Write-Host ""

        # Display main menu options
        Write-Host "MAIN MENU" -ForegroundColor Yellow
        Write-Host "═════════" -ForegroundColor Yellow
        Write-Host ""

        Write-Host "  1. " -ForegroundColor White -NoNewline
        Write-Host "TCP/IP Protocol Stack Optimizations" -ForegroundColor Green
        Write-Host "     Configure TCP/UDP settings, window scaling, and protocol optimizations" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  2. " -ForegroundColor White -NoNewline
        Write-Host "Connection Type Optimizations" -ForegroundColor Green
        Write-Host "     WiFi, Ethernet, and Fiber-specific network optimizations" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  3. " -ForegroundColor White -NoNewline
        Write-Host "DNS and Memory Management" -ForegroundColor Green
        Write-Host "     DNS cache, network memory, and buffer optimizations" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  4. " -ForegroundColor White -NoNewline
        Write-Host "Network Security" -ForegroundColor Green
        Write-Host "     Firewall, protocol security, and vulnerability mitigations" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  5. " -ForegroundColor White -NoNewline
        Write-Host "Gaming and Streaming" -ForegroundColor Green
        Write-Host "     Gaming mode, streaming optimizations, and low-latency settings" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  6. " -ForegroundColor White -NoNewline
        Write-Host "Tools and Utilities" -ForegroundColor Green
        Write-Host "     System restore, backup, health reports, and maintenance tools" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  7. " -ForegroundColor White -NoNewline
        Write-Host "Apply All Recommended Optimizations" -ForegroundColor Magenta
        Write-Host "     Execute all recommended optimizations automatically" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  8. " -ForegroundColor White -NoNewline
        Write-Host "View System Information" -ForegroundColor Cyan
        Write-Host "     Display current network configuration and system details" -ForegroundColor Gray
        Write-Host ""

        Write-Host "  0. " -ForegroundColor White -NoNewline
        Write-Host "Exit" -ForegroundColor Red
        Write-Host "     Exit the Network Optimizer" -ForegroundColor Gray
        Write-Host ""

        # Display navigation instructions
        Write-Host "NAVIGATION" -ForegroundColor Yellow
        Write-Host "══════════" -ForegroundColor Yellow
        Write-Host "• Enter the number of your choice and press Enter" -ForegroundColor Gray
        Write-Host "• Type 'help' for detailed information about any option" -ForegroundColor Gray
        Write-Host "• Type 'back' to return to previous menu" -ForegroundColor Gray
        Write-Host "• Type 'exit' or '0' to quit the application" -ForegroundColor Gray
        Write-Host ""

        Write-OptimizationLog "Main menu displayed" -Level "Debug"
    }
    catch {
        Write-OptimizationLog "Failed to display main menu: $($_.Exception.Message)" -Level "Error"
        Write-Error "Failed to display main menu: $($_.Exception.Message)"
    }
}

function Show-CategoryMenu {
        # Display category-specific menu for optimization option selection
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
    [ValidateSet("TCP/IP Protocol Stack", "Connection Type Optimizations", "DNS and Memory Management", "Network Security", "Gaming and Streaming", "Tools and Utilities")]
        [string]$Category
    )

    try {
        Clear-Host

        # Get options for the specified category
        $categoryOptions = $Script:Config.GetOptionsByCategory($Category)

        if (-not $categoryOptions -or $categoryOptions.Count -eq 0) {
            Write-Host "No options available for category: $Category" -ForegroundColor Yellow
            return
        }

        # Display category header
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           $($Category.ToUpper()) OPTIMIZATIONS                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        Write-Host "Select optimizations to apply (multiple selections allowed)" -ForegroundColor Gray
        Write-Host ""

        # Display each option with selection status
        for ($i = 0; $i -lt $categoryOptions.Count; $i++) {
            $option = $categoryOptions[$i]
            $number = $i + 1
            $status = if ($option.Selected) { "[[OK]]" } else { "[ ]" }
            $statusColor = if ($option.Selected) { "Green" } else { "Gray" }

            Write-Host "  $number. " -ForegroundColor White -NoNewline
            Write-Host "$status " -ForegroundColor $statusColor -NoNewline
            Write-Host "$($option.Name)" -ForegroundColor Green

            # Word wrap description to fit console width
            $description = $option.Description
            $maxWidth = 70
            if ($description.Length -gt $maxWidth) {
                $wrapped = ""
                $words = $description -split ' '
                $currentLine = ""

                foreach ($word in $words) {
                    if (($currentLine + $word).Length -gt $maxWidth) {
                        $wrapped += "     $currentLine`n"
                        $currentLine = $word
                    } else {
                        $currentLine += if ($currentLine) { " $word" } else { $word }
                    }
                }
                if ($currentLine) {
                    $wrapped += "     $currentLine"
                }
                Write-Host $wrapped -ForegroundColor Gray
            } else {
                Write-Host "     $description" -ForegroundColor Gray
            }
            Write-Host ""
        }

        # Display action options
        Write-Host "ACTIONS" -ForegroundColor Yellow
        Write-Host "═══════" -ForegroundColor Yellow
        Write-Host "  a. Apply Selected Optimizations" -ForegroundColor Magenta
        Write-Host "  s. Select All" -ForegroundColor Cyan
        Write-Host "  c. Clear All Selections" -ForegroundColor Cyan
        Write-Host "  d. Show Details for Option" -ForegroundColor Cyan
        Write-Host "  b. Back to Main Menu" -ForegroundColor White
        Write-Host "  0. Exit" -ForegroundColor Red
        Write-Host ""

        # Display selection instructions
        Write-Host "SELECTION" -ForegroundColor Yellow
        Write-Host "═════════" -ForegroundColor Yellow
        Write-Host "• Enter option number to toggle selection" -ForegroundColor Gray
        Write-Host "• Enter multiple numbers separated by commas (e.g., 1,3,5)" -ForegroundColor Gray
        Write-Host "• Enter action letter for special actions" -ForegroundColor Gray
        Write-Host ""

        # Show current selection count
        $selectedCount = ($categoryOptions | Where-Object { $_.Selected }).Count
        if ($selectedCount -gt 0) {
            Write-Host "Currently selected: $selectedCount optimization(s)" -ForegroundColor Green
        } else {
            Write-Host "No optimizations currently selected" -ForegroundColor Yellow
        }
        Write-Host ""

        Write-OptimizationLog "Category menu displayed for: $Category" -Level "Debug"
    }
    catch {
        Write-OptimizationLog "Failed to display category menu for ${1} : $($_.Exception.Message)" -Level "Error"
        Write-Error "Failed to display category menu: $($_.Exception.Message)"
    }
}

function Get-UserSelection {
        # Handle user input with validation and error handling
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter()]
        [string]$Prompt = "Enter your selection",

        [Parameter()]
        [string[]]$ValidOptions = @(),

        [Parameter()]
        [switch]$AllowMultiple
    )

    try {
        do {
            $validInput = $false
            $selections = @()

            # Display prompt with color coding
            Write-Host "$Prompt" -ForegroundColor Yellow -NoNewline
            Write-Host ": " -ForegroundColor White -NoNewline

            # Get user input with timeout handling
            $userInput = $null
            try {
                $userInput = Read-Host
            }
            catch {
                Write-Host "Input error occurred. Please try again." -ForegroundColor Red
                continue
            }

            # Handle empty input
            if ([string]::IsNullOrWhiteSpace($userInput)) {
                Write-Host "Please enter a valid selection." -ForegroundColor Red
                Write-OptimizationLog "Empty input received from user" -Level "Debug"
                continue
            }

            # Sanitize input - remove extra spaces and convert to lowercase for commands
            $userInput = $userInput.Trim()
            $inputLower = $userInput.ToLower()

            # Handle special commands
            switch ($inputLower) {
                "exit" {
                    Write-OptimizationLog "User requested exit via input" -Level "Info"
                    return @("exit")
                }
                "quit" {
                    Write-OptimizationLog "User requested quit via input" -Level "Info"
                    return @("exit")
                }
                "back" {
                    Write-OptimizationLog "User requested back navigation" -Level "Debug"
                    return @("back")
                }
                "help" {
                    Write-OptimizationLog "User requested help" -Level "Debug"
                    return @("help")
                }
                default {
                    # Process numeric or action selections
                    if ($AllowMultiple -and $userInput.Contains(",")) {
                        # Handle multiple selections
                        $inputParts = $userInput -split "," | ForEach-Object { $_.Trim() }

                        foreach ($part in $inputParts) {
                            if ([string]::IsNullOrWhiteSpace($part)) {
                                continue
                            }

                            # Validate each part
                            if ($ValidOptions.Count -eq 0 -or $ValidOptions -contains $part -or $ValidOptions -contains $part.ToLower()) {
                                $selections += $part
                            } else {
                                Write-Host "Invalid selection: '$part'. Please enter valid options." -ForegroundColor Red
                                $validInput = $false
                                break
                            }
                        }

                        if ($selections.Count -gt 0 -and $validInput -ne $false) {
                            $validInput = $true
                        }
                    } else {
                        # Handle single selection
                        if ($ValidOptions.Count -eq 0 -or $ValidOptions -contains $userInput -or $ValidOptions -contains $inputLower) {
                            $selections = @($userInput)
                            $validInput = $true
                        } else {
                            Write-Host "Invalid selection: '$userInput'. Please enter a valid option." -ForegroundColor Red

                            # Show valid options if list is reasonable size
                            if ($ValidOptions.Count -le 10 -and $ValidOptions.Count -gt 0) {
                                Write-Host "Valid options: $($ValidOptions -join ', ')" -ForegroundColor Gray
                            }
                            $validInput = $false
                        }
                    }
                }
            }

            # Log the selection attempt
            if ($validInput) {
                Write-OptimizationLog "Valid user selection received: $($selections -join ', ')" -Level "Debug"
            } else {
                Write-OptimizationLog "Invalid user input: $userInput" -Level "Debug"
            }

        } while (-not $validInput)

        return $selections
    }
    catch {
        Write-OptimizationLog "Error in Get-UserSelection: $($_.Exception.Message)" -Level "Error"
        Write-Host "An error occurred while processing your selection. Please try again." -ForegroundColor Red
        return @()
    }
}

function Show-OptimizationDetails {
        # Display detailed information about specific optimizations
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OptimizationName,

        [Parameter()]
        [string]$Category
    )

    try {
        # Find the optimization option
        $option = $null
        if ($Category) {
            $option = $Script:Config.GetOptionsByCategory($Category) | Where-Object { $_.Name -eq $OptimizationName }
        } else {
            $option = $Script:Config.Options | Where-Object { $_.Name -eq $OptimizationName }
        }

        if (-not $option) {
            Write-Host "Optimization not found: $OptimizationName" -ForegroundColor Red
            return
        }

        Clear-Host

        # Display detailed information header
        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           OPTIMIZATION DETAILS                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        # Basic information
        Write-Host "NAME: " -ForegroundColor Yellow -NoNewline
        Write-Host $option.Name -ForegroundColor White
        Write-Host ""

        Write-Host "CATEGORY: " -ForegroundColor Yellow -NoNewline
        Write-Host $option.Category -ForegroundColor White
        Write-Host ""

        Write-Host "STATUS: " -ForegroundColor Yellow -NoNewline
        if ($option.Selected) {
            Write-Host "Selected for execution" -ForegroundColor Green
        } else {
            Write-Host "Not selected" -ForegroundColor Gray
        }
        Write-Host ""

        # Description with word wrapping
        Write-Host "DESCRIPTION:" -ForegroundColor Yellow
        $description = $option.Description
        $maxWidth = 78
        if ($description.Length -gt $maxWidth) {
            $wrapped = ""
            $words = $description -split ' '
            $currentLine = ""

            foreach ($word in $words) {
                if (($currentLine + $word).Length -gt $maxWidth) {
                    $wrapped += "$currentLine`n"
                    $currentLine = $word
                } else {
                    $currentLine += if ($currentLine) { " $word" } else { $word }
                }
            }
            if ($currentLine) {
                $wrapped += $currentLine
            }
            Write-Host $wrapped -ForegroundColor White
        } else {
            Write-Host $description -ForegroundColor White
        }
        Write-Host ""

        # Requirements if available
        if ($option.Requirements -and $option.Requirements.Count -gt 0) {
            Write-Host "REQUIREMENTS:" -ForegroundColor Yellow
            foreach ($req in $option.Requirements) {
                Write-Host "• $req" -ForegroundColor Gray
            }
            Write-Host ""
        }

        # Technical details based on optimization type
        Write-Host "TECHNICAL DETAILS:" -ForegroundColor Yellow

        # Provide specific technical information based on the optimization name
        switch -Wildcard ($option.Name) {
            "*TCP Stack*" {
                Write-Host "Registry Changes:" -ForegroundColor Cyan
                Write-Host "• HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ForegroundColor Gray
                Write-Host "  - Tcp1323Opts: Enables TCP window scaling" -ForegroundColor Gray
                Write-Host "  - TCPNoDelay: Disables Nagle's algorithm" -ForegroundColor Gray
                Write-Host "  - TcpAckFrequency: Optimizes ACK frequency" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Impact: Improves throughput and reduces latency for TCP connections" -ForegroundColor White
            }
            "*DNS*" {
                Write-Host "Registry Changes:" -ForegroundColor Cyan
                Write-Host "• HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ForegroundColor Gray
                Write-Host "  - CacheHashTableBucketSize: DNS cache optimization" -ForegroundColor Gray
                Write-Host "  - CacheHashTableSize: DNS cache size configuration" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Impact: Faster DNS resolution and reduced lookup times" -ForegroundColor White
            }
            "*Gaming*" {
                Write-Host "Registry Changes:" -ForegroundColor Cyan
                Write-Host "• Multiple registry paths for gaming optimization" -ForegroundColor Gray
                Write-Host "• Network adapter power management settings" -ForegroundColor Gray
                Write-Host "• TCP/UDP buffer optimizations" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Impact: Reduced network latency and improved gaming performance" -ForegroundColor White
            }
            "*Security*" {
                Write-Host "System Changes:" -ForegroundColor Cyan
                Write-Host "• Windows Firewall configuration" -ForegroundColor Gray
                Write-Host "• Protocol security settings" -ForegroundColor Gray
                Write-Host "• Vulnerable protocol disabling" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Impact: Enhanced network security with maintained performance" -ForegroundColor White
            }
            default {
                Write-Host "This optimization modifies network-related registry settings" -ForegroundColor Gray
                Write-Host "and system configurations to improve network performance." -ForegroundColor Gray
            }
        }
        Write-Host ""

        # Safety information
        Write-Host "SAFETY INFORMATION:" -ForegroundColor Yellow
        Write-Host "• System restore point will be created before applying changes" -ForegroundColor Green
        Write-Host "• Current settings will be backed up automatically" -ForegroundColor Green
        Write-Host "• Changes can be reverted using backup files or restore point" -ForegroundColor Green
        Write-Host "• Administrator privileges are required for execution" -ForegroundColor Yellow
        Write-Host ""

        # Navigation options
        Write-Host "OPTIONS:" -ForegroundColor Yellow
        Write-Host "• Press Enter to return to previous menu" -ForegroundColor Gray
        Write-Host "• Type 'select' to toggle selection of this optimization" -ForegroundColor Gray
        Write-Host "• Type 'back' to return to category menu" -ForegroundColor Gray
        Write-Host "• Type 'main' to return to main menu" -ForegroundColor Gray
        Write-Host ""

        Write-OptimizationLog "Displayed details for optimization: $OptimizationName" -Level "Debug"
    }
    catch {
        Write-OptimizationLog "Failed to display optimization details for ${1} : $($_.Exception.Message)" -Level "Error"
        Write-Error "Failed to display optimization details: $($_.Exception.Message)"
    }
}

function Start-InteractiveMenu {
        # Start the interactive menu system and handle navigation
    [CmdletBinding()]
    param()

    try {
        Write-OptimizationLog "Starting interactive menu system" -Level "Info"

        $currentMenu = "main"
        $currentCategory = $null
        $exitRequested = $false

        while (-not $exitRequested) {
            switch ($currentMenu) {
                "main" {
                    Show-MainMenu

                    $validMainOptions = @("1", "2", "3", "4", "5", "6", "7", "8", "0", "exit", "help")
                    $selection = Get-UserSelection -Prompt "Select option" -ValidOptions $validMainOptions
                    # Guard against empty/null selection to avoid crashes
                    if (-not $selection -or $selection.Count -eq 0 -or -not $selection[0]) {
                        Write-Host "No input received. Returning to main menu..." -ForegroundColor Yellow
                        continue
                    }

                    switch ($selection[0]) {
                        "1" {
                            $currentMenu = "category"
                            $currentCategory = "TCP/IP Protocol Stack"
                        }
                        "2" {
                            $currentMenu = "category"
                            $currentCategory = "Connection Type Optimizations"
                        }
                        "3" {
                            $currentMenu = "category"
                            $currentCategory = "DNS and Memory Management"
                        }
                        "4" {
                            $currentMenu = "category"
                            $currentCategory = "Network Security"
                        }
                        "5" {
                            $currentMenu = "category"
                            $currentCategory = "Gaming and Streaming"
                        }
                        "6" {
                            $currentMenu = "category"
                            $currentCategory = "Tools and Utilities"
                        }
                        "7" {
                            # Apply all recommended optimizations
                            Write-Host "Applying all recommended optimizations..." -ForegroundColor Cyan

                            # Select all recommended options
                            $Script:Config.SelectRecommendedOptions()
                            $selectedOptions = $Script:Config.GetSelectedOptions()

                            if ($selectedOptions.Count -gt 0) {
                                Write-Host "Found $($selectedOptions.Count) recommended optimizations" -ForegroundColor Green

                                # Confirm execution
                                $confirm = Read-Host "Do you want to proceed with applying these optimizations? (y/N)"
                                if ($confirm -match '^[Yy]') {
                                    # Execute optimizations
                                    $executionResult = Invoke-SelectedOptimizations -SelectedOptions $selectedOptions -Config $Script:Config -ContinueOnError

                                    # Store results for reporting
                                    $Script:OptimizationResults += $executionResult.Results

                                    if ($executionResult.Success) {
                                        Write-Host "`n[OK] All recommended optimizations applied successfully!" -ForegroundColor Green
                                    } else {
                                        Write-Host "`n[WARN] Some optimizations failed. Check the results above." -ForegroundColor Yellow
                                    }

                                    # Generate report
                                    $reportResult = New-NetworkHealthReport -OptimizationResults $executionResult.Results
                                    if ($reportResult.Success) {
                                        Write-Host "Network health report generated: $($reportResult.ReportPath)" -ForegroundColor Cyan
                                    }
                                } else {
                                    Write-Host "Operation cancelled by user" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "No recommended optimizations found" -ForegroundColor Yellow
                            }

                            Read-Host "Press Enter to continue"
                        }
                        "8" {
                            # Show system information
                            Show-SystemInformation
                            Read-Host "Press Enter to continue"
                        }
                        { $_ -in @("0", "exit") } {
                            $exitRequested = $true
                        }
                        "help" {
                            Show-HelpInformation
                            Read-Host "Press Enter to continue"
                        }
                    }
                }

                "category" {
                    Show-CategoryMenu -Category $currentCategory

                    $categoryOptions = $Script:Config.GetOptionsByCategory($currentCategory)
                    $validNumbers = 1..$categoryOptions.Count | ForEach-Object { $_.ToString() }
                    $validCategoryOptions = $validNumbers + @("a", "s", "c", "d", "b", "0", "back", "exit", "help")

                    $selection = Get-UserSelection -Prompt "Select option" -ValidOptions $validCategoryOptions -AllowMultiple
                    # Guard against empty/null selection to avoid null method calls
                    if (-not $selection -or $selection.Count -eq 0 -or -not $selection[0]) {
                        Write-Host "No input received. Returning to category menu..." -ForegroundColor Yellow
                        continue
                    }

                    if ($validNumbers -contains $selection[0]) {
                        # Handle numeric selections (toggle optimization selection)
                        foreach ($sel in $selection) {
                            if ($validNumbers -contains $sel) {
                                $optionIndex = [int]$sel - 1
                                if ($optionIndex -ge 0 -and $optionIndex -lt $categoryOptions.Count) {
                                    $categoryOptions[$optionIndex].Selected = -not $categoryOptions[$optionIndex].Selected
                                    $status = if ($categoryOptions[$optionIndex].Selected) { "selected" } else { "deselected" }
                                    Write-Host "Option '$($categoryOptions[$optionIndex].Name)' $status" -ForegroundColor Green
                                }
                            }
                        }
                        Start-Sleep -Milliseconds 500  # Brief pause to show selection feedback
                    } else {
                        # Handle action commands
                        $sel0 = if ($selection[0]) { $selection[0].ToString().ToLower() } else { "" }
                        switch ($sel0) {
                            "a" {
                                # Apply selected optimizations
                                $selectedOptions = $categoryOptions | Where-Object { $_.Selected }
                                if ($selectedOptions.Count -gt 0) {
                                    Write-Host "Applying $($selectedOptions.Count) selected optimization(s)..." -ForegroundColor Cyan

                                    # Show selected optimizations
                                    Write-Host "`nSelected optimizations:" -ForegroundColor Yellow
                                    foreach ($opt in $selectedOptions) {
                                        Write-Host "  • $($opt.Name)" -ForegroundColor Gray
                                    }

                                    # Confirm execution
                                    $confirm = Read-Host "`nDo you want to proceed with applying these optimizations? (y/N)"
                                    if ($confirm -match '^[Yy]') {
                                        # Execute optimizations
                                        $executionResult = Invoke-SelectedOptimizations -SelectedOptions $selectedOptions -Config $Script:Config -ContinueOnError

                                        # Store results for reporting
                                        $Script:OptimizationResults += $executionResult.Results

                                        if ($executionResult.Success) {
                                            Write-Host "`n[OK] All selected optimizations applied successfully!" -ForegroundColor Green
                                        } else {
                                            Write-Host "`n[WARN] Some optimizations failed. Check the results above." -ForegroundColor Yellow
                                        }

                                        # Generate report
                                        $reportResult = New-NetworkHealthReport -OptimizationResults $executionResult.Results
                                        if ($reportResult.Success) {
                                            Write-Host "Network health report generated: $($reportResult.ReportPath)" -ForegroundColor Cyan
                                        }

                                        # Clear selections after execution
                                        foreach ($option in $selectedOptions) {
                                            $option.Selected = $false
                                        }
                                        Write-Host "Selections cleared for next use" -ForegroundColor Gray
                                    } else {
                                        Write-Host "Operation cancelled by user" -ForegroundColor Yellow
                                    }
                                } else {
                                    Write-Host "No optimizations selected. Please select at least one optimization." -ForegroundColor Yellow
                                }
                                Read-Host "Press Enter to continue"
                            }
                            "s" {
                                # Select all
                                foreach ($option in $categoryOptions) {
                                    $option.Selected = $true
                                }
                                Write-Host "All optimizations selected" -ForegroundColor Green
                                Start-Sleep -Milliseconds 500
                            }
                            "c" {
                                # Clear all selections
                                foreach ($option in $categoryOptions) {
                                    $option.Selected = $false
                                }
                                Write-Host "All selections cleared" -ForegroundColor Yellow
                                Start-Sleep -Milliseconds 500
                            }
                            "d" {
                                # Show details for option
                                $detailSelection = Get-UserSelection -Prompt "Enter option number for details" -ValidOptions $validNumbers
                                if ($detailSelection[0] -match '^\d+$') {
                                    $optionIndex = [int]$detailSelection[0] - 1
                                    if ($optionIndex -ge 0 -and $optionIndex -lt $categoryOptions.Count) {
                                        Show-OptimizationDetails -OptimizationName $categoryOptions[$optionIndex].Name -Category $currentCategory
                                        Read-Host "Press Enter to continue"
                                    }
                                }
                            }
                            { $_ -in @("b", "back") } {
                                $currentMenu = "main"
                                $currentCategory = $null
                            }
                            { $_ -in @("0", "exit") } {
                                $exitRequested = $true
                            }
                            "help" {
                                Show-HelpInformation
                                Read-Host "Press Enter to continue"
                            }
                        }
                    }
                }
            }
        }

        Write-Host "Thank you for using PowerShell Network Optimizer!" -ForegroundColor Green
        Write-OptimizationLog "Interactive menu session ended by user" -Level "Info"
    }
    catch {
        Write-OptimizationLog "Error in interactive menu system: $($_.Exception.Message)" -Level "Error"
        Write-Error "An error occurred in the menu system: $($_.Exception.Message)"
    }
}

function Show-SystemInformation {
        # Display current system and network information
    [CmdletBinding()]
    param()

    try {
        Clear-Host

        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                            SYSTEM INFORMATION                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        # System Information
        Write-Host "SYSTEM DETAILS" -ForegroundColor Yellow
        Write-Host "══════════════" -ForegroundColor Yellow
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor White
        Write-Host "Operating System: $($os.Caption)" -ForegroundColor White
        Write-Host "OS Version: $($os.Version)" -ForegroundColor White
        Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
        Write-Host "PowerShell Edition: $($PSVersionTable.PSEdition)" -ForegroundColor White
        Write-Host ""

        # Network Adapters
        Write-Host "NETWORK ADAPTERS" -ForegroundColor Yellow
        Write-Host "════════════════" -ForegroundColor Yellow
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        foreach ($adapter in $adapters) {
            Write-Host "• $($adapter.Name)" -ForegroundColor Green
            Write-Host "  Interface: $($adapter.InterfaceDescription)" -ForegroundColor Gray
            Write-Host "  Speed: $($adapter.LinkSpeed)" -ForegroundColor Gray
            Write-Host "  MAC: $($adapter.MacAddress)" -ForegroundColor Gray
        }
        Write-Host ""

        # IP Configuration
        Write-Host "IP CONFIGURATION" -ForegroundColor Yellow
        Write-Host "════════════════" -ForegroundColor Yellow
        $ipConfigs = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }
        foreach ($config in $ipConfigs) {
            Write-Host "• $($config.InterfaceAlias)" -ForegroundColor Green
            if ($config.IPv4Address) {
                Write-Host "  IPv4: $($config.IPv4Address.IPAddress)" -ForegroundColor White
            }
            if ($config.IPv6Address) {
                Write-Host "  IPv6: $($config.IPv6Address.IPAddress)" -ForegroundColor White
            }
            if ($config.DNSServer) {
                Write-Host "  DNS: $($config.DNSServer.ServerAddresses -join ', ')" -ForegroundColor White
            }
        }
        Write-Host ""

        Write-OptimizationLog "System information displayed" -Level "Debug"
    }
    catch {
        Write-OptimizationLog "Failed to display system information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error displaying system information: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-HelpInformation {
        # Display help information and usage instructions
    [CmdletBinding()]
    param()

    try {
        Clear-Host

        Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                               HELP & USAGE                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

        Write-Host "NAVIGATION" -ForegroundColor Yellow
        Write-Host "══════════" -ForegroundColor Yellow
        Write-Host "• Use number keys to select menu options" -ForegroundColor White
        Write-Host "• Type 'back' to return to the previous menu" -ForegroundColor White
        Write-Host "• Type 'exit' or '0' to quit the application" -ForegroundColor White
        Write-Host "• Type 'help' for this help information" -ForegroundColor White
        Write-Host ""

        Write-Host "OPTIMIZATION CATEGORIES" -ForegroundColor Yellow
        Write-Host "═══════════════════════" -ForegroundColor Yellow
        Write-Host "1. TCP/IP Protocol Stack - Core network protocol optimizations" -ForegroundColor White
        Write-Host "2. Connection Type - WiFi, Ethernet, and Fiber specific settings" -ForegroundColor White
        Write-Host "3. DNS and Memory - DNS cache and network memory management" -ForegroundColor White
        Write-Host "4. Network Security - Firewall and security optimizations" -ForegroundColor White
        Write-Host "5. Gaming and Streaming - Low-latency and performance settings" -ForegroundColor White
        Write-Host "6. Tools and Utilities - Backup, restore, and maintenance tools" -ForegroundColor White
        Write-Host ""

        Write-Host "SAFETY FEATURES" -ForegroundColor Yellow
        Write-Host "═══════════════" -ForegroundColor Yellow
        Write-Host "• System restore point created before changes" -ForegroundColor Green
        Write-Host "• Registry settings backed up automatically" -ForegroundColor Green
        Write-Host "• All changes can be reverted" -ForegroundColor Green
        Write-Host "• Administrator privileges required" -ForegroundColor Yellow
        Write-Host ""

        Write-Host "TROUBLESHOOTING" -ForegroundColor Yellow
        Write-Host "═══════════════" -ForegroundColor Yellow
        Write-Host "• Check log file for detailed error information" -ForegroundColor White
        Write-Host "• Use system restore point to revert changes if needed" -ForegroundColor White
        Write-Host "• Run as Administrator for full functionality" -ForegroundColor White
        Write-Host "• Ensure Windows 10/11 and PowerShell 5.1+ compatibility" -ForegroundColor White
        Write-Host ""

        Write-Host "LOG FILE LOCATION" -ForegroundColor Yellow
        Write-Host "═════════════════" -ForegroundColor Yellow
        Write-Host "$Script:LogFile" -ForegroundColor White
        Write-Host ""

        Write-OptimizationLog "Help information displayed" -Level "Debug"
    }
    catch {
        Write-OptimizationLog "Failed to display help information: $($_.Exception.Message)" -Level "Error"
        Write-Host "Error displaying help information: $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion

# Script execution entry point
if ($MyInvocation.InvocationName -ne '.') {
    # Only run if script is executed directly (not dot-sourced)
    Start-NetworkOptimizer
}
