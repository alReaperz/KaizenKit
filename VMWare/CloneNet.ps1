<#
.SYNOPSIS
   Clone network configurations (Virtual Switches and Port Groups) from one ESXi host to another.

.DESCRIPTION
   This script connects to a source and a target ESXi host, cloning the virtual switches and port groups 
   from the source to the target host. It prompts separately for source and target credentials (with an option 
   to use the same credential for both), logs operations with UTC timestamps (with a trailing "Z") to a log file 
   (clonenet.log) in the same directory as the script, and uses proper error handling. Optionally, you can also 
   clone VMkernel adapters (this section is commented out).

.PARAMETER SourceHost
   The hostname or IP address of the source ESXi host.

.PARAMETER TargetHost
   The hostname or IP address of the target ESXi host.

.PARAMETER SourceCredential
   (Optional) A PSCredential object for connecting to the source host. If not provided, you will be prompted.

.PARAMETER TargetCredential
   (Optional) A PSCredential object for connecting to the target host. If not provided, you will be prompted 
   with an option to use the same credential as the source.

.EXAMPLE
   .\Clone-NetConfig.ps1 -SourceHost "esxi2.alreaperz.ovh" -TargetHost "esxi3.alreaperz.ovh"

.NOTES
   Tested with both PowerShell 5 and PowerShell 7.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SourceHost,

    [Parameter(Mandatory = $true)]
    [string]$TargetHost,

    [Parameter(Mandatory = $false)]
    [PSCredential]$SourceCredential,

    [Parameter(Mandatory = $false)]
    [PSCredential]$TargetCredential
)

# Instruct PowerCLI to ignore invalid SSL certificates (useful for self-signed certificates)
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# Determine the directory of the script (works in PS5 and PS7)
$ScriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$LogFile = Join-Path -Path $ScriptDirectory -ChildPath "CloneNet.log"

# Logging function using UTC datetime stamps (with trailing "Z")
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $logEntry = "$timestamp [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Prompt for the source credential if not provided
if (-not $SourceCredential) {
    $sourceCredential = Get-Credential -Message "Enter credentials for the source ESXi host ($SourceHost)"
} else {
    $sourceCredential = $SourceCredential
}

# Determine target credential:
if (-not $TargetCredential) {
    $targetPrompt = Read-Host "Press Enter if using the same credential for target host ($TargetHost), or type any text to provide separate credentials"
    if ([string]::IsNullOrWhiteSpace($targetPrompt)) {
         $targetCredential = $sourceCredential
         Write-Log "Using the same credential for target host ($TargetHost) as for source host."
    } else {
         $targetCredential = Get-Credential -Message "Enter credentials for the target ESXi host ($TargetHost)"
    }
} else {
    $targetCredential = $TargetCredential
}

# Main logic wrapped in try/catch/finally for error handling
try {
    Write-Log "Starting network cloning process."

    # Connect to the source ESXi host
    Write-Log "Connecting to source ESXi host: $SourceHost."
    Connect-VIServer -Server $SourceHost -User $sourceCredential.UserName `
                     -Password ($sourceCredential.GetNetworkCredential().Password) -ErrorAction Stop

    # Connect to the target ESXi host
    Write-Log "Connecting to target ESXi host: $TargetHost."
    Connect-VIServer -Server $TargetHost -User $targetCredential.UserName `
                     -Password ($targetCredential.GetNetworkCredential().Password) -ErrorAction Stop

    # Retrieve ESXi host objects
    Write-Log "Retrieving ESXi host objects."
    $esxiSource = Get-VMHost -Name $SourceHost -ErrorAction Stop
    $esxiTarget = Get-VMHost -Name $TargetHost -ErrorAction Stop

    # Clone Virtual Switches
    Write-Log "Cloning Virtual Switches from $SourceHost to $TargetHost."
    $vswitches = Get-VirtualSwitch -VMHost $esxiSource -ErrorAction Stop
    foreach ($vswitch in $vswitches) {
        $existingSwitch = Get-VirtualSwitch -VMHost $esxiTarget | Where-Object { $_.Name -eq $vswitch.Name }
        if (-not $existingSwitch) {
            Write-Log "Creating Virtual Switch '$($vswitch.Name)' on $TargetHost."
            New-VirtualSwitch -VMHost $esxiTarget -Name $vswitch.Name -Mtu $vswitch.Mtu -ErrorAction Stop
        } else {
            Write-Log "Virtual Switch '$($vswitch.Name)' already exists on $TargetHost, skipping."
        }
    }

    # Clone Virtual Port Groups for Standard Switches
    Write-Log "Cloning Virtual Port Groups from $SourceHost to $TargetHost."
    $portgroups = Get-VirtualPortGroup -VMHost $esxiSource -ErrorAction Stop
    foreach ($pg in $portgroups) {
        # Find the matching virtual switch on the target host
        $targetSwitch = Get-VirtualSwitch -VMHost $esxiTarget | Where-Object { $_.Name -eq $pg.VirtualSwitch.Name }
        if ($null -eq $targetSwitch) {
            Write-Log "Virtual Switch '$($pg.VirtualSwitch.Name)' not found on $TargetHost, skipping port group '$($pg.Name)'." "WARNING"
            continue
        }

        # Check if the port group already exists on the target switch
        $existingPG = Get-VirtualPortGroup -VMHost $esxiTarget | Where-Object { $_.Name -eq $pg.Name -and $_.VirtualSwitch.Name -eq $targetSwitch.Name }
        if (-not $existingPG) {
            Write-Log "Creating Port Group '$($pg.Name)' on $TargetHost."
            New-VirtualPortGroup -VirtualSwitch $targetSwitch -Name $pg.Name -VLanId $pg.VLanId -ErrorAction Stop
        } else {
            Write-Log "Port Group '$($pg.Name)' already exists on $TargetHost, skipping."
        }
    }

    # Optional: Clone VMkernel Adapters (uncomment if needed)
    <#
    Write-Log "Cloning VMkernel Adapters from $SourceHost to $TargetHost."
    $vmkernels = Get-VMHostNetworkAdapter -VMHost $esxiSource -VMKernel -ErrorAction Stop
    foreach ($vmk in $vmkernels) {
        Write-Log "Creating VMkernel Adapter for Port Group '$($vmk.PortGroupName)' on $TargetHost."
        New-VMHostNetworkAdapter -PortGroup $vmk.PortGroupName -IP $vmk.IP -SubnetMask $vmk.SubnetMask -VMHost $esxiTarget -ErrorAction Stop
    }
    #>

    Write-Log "Network cloning process completed successfully."
}
catch {
    Write-Log "An error occurred: $_" "ERROR"
}
finally {
    # Disconnect from ESXi hosts (suppress any errors during disconnect)
    try {
        Write-Log "Disconnecting from source ESXi host: $SourceHost."
        Disconnect-VIServer -Server $SourceHost -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Error disconnecting from source host: $_" "WARNING"
    }
    try {
        Write-Log "Disconnecting from target ESXi host: $TargetHost."
        Disconnect-VIServer -Server $TargetHost -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Error disconnecting from target host: $_" "WARNING"
    }
}
