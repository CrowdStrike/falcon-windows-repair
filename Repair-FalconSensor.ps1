<#
    .SYNOPSIS 
        PS v3 or higher required
        TLS 1.2 required
    .NOTES
        Version:   v1.3.0
        Author:    CrowdStrike, Inc.
        Usage:     Use at your own risk. While all efforts have been made to ensure this script works as expected, you should test
                   in your own environment. 
        Requirements:    
            Falcon Administrator role required for Created API access
            API Key with following permissions: 'Sensor Download: Read'
            PowerShell v3 or higher
            TLS 1.2 minimum
            Sign the script, or execute with bypass        
    .DESCRIPTION
        Determines state of Falcon Sensor and repairs as necessary. Additional checks for bad channel file are performed, and file 
        is removed if deemed bad.
    .PARAMETER ClientId
        OAuth2 API Client Id from the source tenant.  
    .PARAMETER ClientSecret
        OAuth2 API Client Secret from the source tenant.
    .PARAMETER Cloud
        Falcon Cloud to utilize. Available options: 'us-1', 'us-2', 'eu-1', 'us-gov-1'  
    .PARAMETER FlightControl
        Only set value to $true if your Falcon environment utilzes Flight Control for parent/child relationships
#>


<# -------------------      Begin Editable Region. -------------- #>
[CmdletBinding()]
param( 

    # Paste Client ID here
    [string]$ClientId = '',
     
    # Paste Client Secret here
    [string]$ClientSecret = '',

    # Put which cloud your environment is hosted on
    [ValidateSet('eu-1', 'us-1', 'us-2', 'us-gov-1')]
    [string]$Cloud = '',

    # Set value to $true if using a Flight Control enabled CID
    [bool]$FlightControl = $false

)
<# ----------------      END Editable Region. ----------------- #>

begin {
    # Check for PowerShell 3.0 and Tls12
    if ($PSVersionTable.PSVersion -lt '3.0')
       { throw "[!] Error: This script requires a miniumum PowerShell 3.0" }
    if (!([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')) {
        if (([enum]::GetNames([Net.SecurityProtocolType]) -contains [Net.SecurityProtocolType]::Tls12)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } else {
            throw "[!] Error: Unable to use Tls12. Please review .NET and PowerShell requirenments."
        }
    }
    # Check for necessary cmdlets
    $cmds = @(
        "ConvertFrom-Json",
        "ConvertTo-Json",
        "Get-ChildItem",
        "Get-FileHash",
        "Get-Process",
        "Get-Service",
        "Invoke-WebRequest",
        "Measure-Object",
        "Remove-Item",
        "Start-Process",
        "Test-Path",
        "Write-Output"
    )   
    foreach ($cmd in $cmds) {
        if (-not (Get-Command $cmd -errorAction SilentlyContinue)) {
            throw "[!] Error: The term '$($cmd)' is not recognized as the name of a cmdlet."
        }
    }
    # Check current user has an administrator role
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not ($currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        throw "[!] Error: This script requires administrative privileges."
    }
    # Check environment isn't 32-bit PowerShell
    if ([Environment]::Is64BitProcess -ne [Environment]::Is64BitOperatingSystem) {
        throw "[!] Error: 32-bit PowerShell process does not match the 64-bit Operating System"
    }
} 
process {
    $repairHost = $false
    $tempFolderCreated = $false
    $remediationEpoch = 1721370420  # Official CrowdStrike July 19th incident epoch +1hr
    $csFolderPath = "C:\Program Files\CrowdStrike"
    $csDriverFolderPath = "C:\Windows\System32\drivers\CrowdStrike"
    $InstallerPath = 'C:\temp\WindowsSensor.exe'
    $InstallArgs = '/repair /quiet /norestart /forcedowngrade ProvNoWait=1'
    $maintenceTokenReq = $false

    # Check if csagent is not running and delete 291 channel file
    try {
        if ((Get-Service -Name "csagent").Status -ne "Running") {
            $driverFiles = Get-ChildItem $csDriverFolderPath -ErrorAction Stop
            foreach ($file in $driverFiles) {
                if ($file.FullName -like "*C-00000291*") {
                    # Remove 291 channel files, sensor restores file after reboot
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop  
                    Write-Output "[+] Channel File '$($file.Fullname)' deleted"
                }
            } 
        }                  
    } catch [System.Management.Automation.ItemNotFoundException] {
        $repairHost = $true
    } catch [Microsoft.Powershell.Commands.ServiceCommandException] {
        $repairHost = $true
    } catch {
        throw "[!] Error: Attempting to delete 291 channel files: $_"
    }    
    try {
        # Check CrowdStrike folders haven't been renamed/deleted
        if (-not (Test-Path $csFolderPath) -or -not (Test-Path $csDriverFolderPath)) {
            $repairHost = $true
            Write-Output "[+] '$csFolderPath' or '$csDriverFolderPath' could not be found, repairing sensor.."
            if (-not (Test-Path $csDriverFolderPath)) {
                $maintenceTokenReq = $true
            }
        } else {
            # Check if folders could of been modified
            $csFolderTime = Get-Item -Path $csFolderPath | Select-Object -ExpandProperty LastWriteTimeUtc;
            $csFolderTimeEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csFolderTime).TotalSeconds)
            $csFolderCreationTime = (Get-Item $csFolderPath).CreationTime
            $csFolderCreationEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csFolderCreationTime).TotalSeconds)
            $csDriverFolderTime = Get-Item -Path $csDriverFolderPath | Select-Object -ExpandProperty LastWriteTimeUtc;
            $csDriverFolderTimeEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csDriverFolderTime).TotalSeconds)
            $csDriverFolderCreationTime = (Get-Item $csDriverFolderPath).CreationTime
            $csDriverFolderCreationEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csDriverFolderCreationTime).TotalSeconds)
            if (($csFolderCreationEpoch -lt $remediationEpoch) -or ($csDriverFolderCreationEpoch -lt $remediationEpoch)) {
                if (($csFolderTimeEpoch -gt $remediationEpoch) -or ($csDriverFolderTimeEpoch -gt $remediationEpoch)) {
                    $repairHost = $true
                    Write-Output "[+] Potential issue found within '$csFolderPath' or '$csDriverFolderPath', repairing sensor.."
                    if ($csDriverFolderTimeEpoch -gt $remediationEpoch) {
                        $maintenceTokenReq = $true
                    }
                }
            }
        }
        # Check CsFalconService and csagent
        if (((Get-Service -Name "CsFalconService").Status -ne "Running") -or ((Get-Service -Name "csagent").Status -ne "Running")) {
            $repairHost = $true
            Write-Output "[+] 'csagent' or 'CsFalconService' found not running, repairing sensor.."
            if ((Get-Service -Name "CsFalconService").Status -ne "Running") {
                $maintenceTokenReq = $true
            }
        }
        if (-not (Test-Path "C:\Windows\System32\drivers\CrowdStrike\csagent.sys") -or -not (Test-Path "C:\Program Files\CrowdStrike\CsFalconService.exe")) {
            $repairHost = $true
            Write-Output "[+] 'csagent.sys' or 'CsFalconService.exe' could not be found, repairing sensor.."
            if (-not (Test-Path "C:\Program Files\CrowdStrike\CsFalconService.exe")) {
                $maintenceTokenReq = $true
            }
        }   
    } catch {
        $repairHost = $true
        Write-Output '[+] Sensor issue found, repairing sensor..'
    }    
    if ($repairHost) {
        # Validate if API credentials have been set.
        if ((-not $ClientId) -or (-not $ClientSecret)) {
            throw "[!] Error: API credentials missing."
        } elseif ($ClientId -notmatch "^[a-fA-F0-9]{32}$") {
            throw "[!] Error: SourceID '$ClientId' does not match proper formatting, please ensure SourceID is correct."
        } elseif ($ClientSecret -notmatch "^[a-zA-Z0-9]{40}$") {
            throw "[!] Error: SourceSecret '$ClientSecret' does not match proper formatting, please ensure SourceSecret is correct."
        }
        if (-not (Test-Path -Path "C:\temp\")) {
            # Create temp folder if it doesn't exist
            New-Item -Path "C:\" -Name "temp" -ItemType "directory"
            $tempFolderCreated = $true
        }
        $Retries=0
        do {
            if (-not $Cloud) {
                throw "[!] Error: Cloud not specified, please specify -Cloud in arguments."
            }
            switch ($Cloud) {
                'eu-1' { $SrcHostname = 'https://api.eu-1.crowdstrike.com' }
                'us-1' { $SrcHostname = 'https://api.crowdstrike.com' }
                'us-2' { $SrcHostname = 'https://api.us-2.crowdstrike.com' }
                'us-gov-1' { $SrcHostname = 'https://api.laggar.gcw.crowdstrike.com' }
            }            
            if ($FlightControl) {
                try {
                    # Get CID value from registry
                    $CurrentCID = ''
                    if (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name CU -ErrorAction SilentlyContinue) {
                        $CurrentCID = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
                                    "{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
                                    "\Default") -Name CU -ErrorAction SilentlyContinue).CU)).ToLower() -replace '-','')
                    } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue) {
                        $CurrentCID = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services" +
                                    "\CSAgent\Sim") -Name CU -ErrorAction SilentlyContinue).CU)).ToLower() -replace '-','')
                    }
                    # Ensure CID matches regex criteria
                    if (($CurrentCID) -and ($CurrentCID -match "^[a-fA-F0-9]{32}$")) {
                        $Param = @{
                            Uri = "$($SrcHostname)/oauth2/token"
                            Method = 'post'
                            Headers = @{
                                accept = 'application/json'
                                'content-type' = 'application/x-www-form-urlencoded'
                            }
                            Body = @{
                                'client_id' = $ClientId
                                'client_secret' = $ClientSecret
                                'member_cid' = $CurrentCID
                            }
                        } 
                    } else {
                        Write-Output "[+] CID '$CurrentCID' does not match formatting criteria for CID. Continuing with script.."
                        $Param = @{
                            Uri = "$($SrcHostname)/oauth2/token"
                            Method = 'post'
                            Headers = @{
                                accept = 'application/json'
                                'content-type' = 'application/x-www-form-urlencoded'
                            }
                            Body = @{
                                'client_id' = $ClientId
                                'client_secret' = $ClientSecret
                            }
                        } 
                    }
                } catch {
                    Write-Output "[+] Unable to obtain CID from registry. Please re-run script with an API key scoped from child CID if error occurs."
                }                
            } else {
                $Param = @{
                    Uri = "$($SrcHostname)/oauth2/token"
                    Method = 'post'
                    Headers = @{
                        accept = 'application/json'
                        'content-type' = 'application/x-www-form-urlencoded'
                    }
                    Body = @{
                        'client_id' = $ClientId
                        'client_secret' = $ClientSecret
                    }
                } 
            }
            # Get API Token
            Write-Output "[+] Generating Falcon Token.."
            $SrcToken = try {(Invoke-WebRequest @Param -UseBasicParsing -MaximumRedirection 0)
                        } catch {
                            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                                Write-Output $_.ErrorDetails.Length
                                $_.ErrorDetails | ConvertFrom-Json
                            } elseif ($_.Exception.Response) {
                                if ($_.Exception.Response.StatusCode -eq 403) {
                                    throw "[!] Error: Unable to request token from source cloud $($Cloud) using client id $($ClientId) due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review source API credentials."
                                }
                            } else {
                                $_.Exception
                            }
                        }    
            if ($SrcToken.StatusCode -ne 201) {
                if (!$SrcToken.Headers) {
                    Write-Host "[!] Error: Unable to request token. Please check API credentials or connectivity. Current response is: $($SrcToken)"
                    break
                } else {
                    $Cloud=$SrcToken.Headers.'X-Cs-Region'
                }
            }
            $Retries++
        } while ($SrcToken.StatusCode -ne 201 -and $Retries -le 4)    
        $SrcToken = ($SrcToken | ConvertFrom-Json)    
        if (-not $SrcToken.access_token) {
            throw "[!] Error: Unable to request token from source cloud $($Cloud) using client id $($ClientId). Return was: $($SrcToken)"
        }                        
        # Get all Windows sensor builds
        $Param = @{
            Uri = "$($SrcHostname)/sensors/combined/installers/v1?filter=platform%3A%27windows%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
            }
        }
        $Installers = try {
            (Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json)
        } catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "[!] Error: Unable to determine hash to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($ClientId) or set sensor hash manually."
                }
            } else {
                $_.Exception
            }
        } 
        # Check that there isn't already a bad installer
        $Hash = $Installers.resources[0].sha256                
        if (Test-Path $InstallerPath) {
            if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
                Remove-Item $InstallerPath
            }
        }    
        if ((Test-Path $InstallerPath) -eq $false) {
            # Download newest sensor
            $Param = @{
                Uri = "$($SrcHostname)/sensors/entities/download-installer/v1?id=" + $Hash
                Method = 'get'
                Header = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
                }
                OutFile = $InstallerPath
            }
            Write-Output "[+] Downloading installer to '$InstallerPath'.."
            $Request = try {
                Invoke-WebRequest @Param -UseBasicParsing
            } catch {
                if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                    Write-Output $_.ErrorDetails.Length
                    $_.ErrorDetails | ConvertFrom-Json
                } elseif ($_.Exception.Response) {
                    if ($_.Exception.Response.StatusCode -eq 403) {
                        throw "[!] Error: Unable to download sensor file to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($ClientId) or upload sensor file manually at $($InstallerPath)."
                    }
                } else {
                    $_.Exception
                }
            }
            if ((Test-Path $InstallerPath) -eq $false) {
                throw "[!] Error: Unable to locate $($InstallerPath)"
            }
            if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
                throw "[!] Error: $($InstallerPath) hash differs. File looks like corrupted."
            }
        }     
        if ($maintenceTokenReq) {
            # Get sensor maintenance token    
            $Param = @{
                Uri = "$($SrcHostname)/policy/combined/reveal-uninstall-token/v1"
                Method = 'post'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/json'
                    authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
                }
                Body = @{
                    audit_message = "Repair-FalconSensor"
                    device_id = "MAINTENANCE"
                } | ConvertTo-Json
            }
            Write-Output "[+] Getting bulk sensor maintence token from Falcon API.."
            $Request = try {Invoke-WebRequest @Param -UseBasicParsing | ConvertFrom-Json
            } catch {
                if ($_.ErrorDetails) {
                    $_.ErrorDetails | ConvertFrom-Json
                }
                else {
                    $_.Exception
                }
            }
            if (-not $Request.resources) {
                throw "[!] Error: Unable to retrieve maintenance token from source cloud '$($Cloud)' using client id $($ClientId). Return was: $($Request.errors.message)."
            } else {
                $InstallArgs += " MAINTENANCE_TOKEN=$($Request.resources.uninstall_token)"
            }
        }        
        # Start the sensor installer to begin repair process        
        Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgs -PassThru -Wait | ForEach-Object {
            Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning recover; sensor will become unresponsive..."
            Write-Output "[$($_.Id)] Beginning recover using the following arguments: '$($InstallArgs)' ..."
        }
        # Clean up
        try {
            if ($tempFolderCreated) {
                Remove-Item ($InstallerPath | Split-Path -Parent) -Force -Recurse -ErrorAction SilentlyContinue
                Write-Output "[+] '$($InstallerPath | Split-Path -Parent)' and '$InstallerPath' removed."
            } else {
                Remove-Item $InstallerPath -Force -Recurse -ErrorAction SilentlyContinue
                Write-Output "[+] '$InstallerPath' removed."
            }
        }
        catch {
            if ($tempFolderCreated) {
                Write-Output "[!] Error: Deleting '$($InstallerPath | Split-Path -Parent)' and '$InstallerPath'. Manual removal is required."
            } else {
                Write-Output "[!] Error: Deleting $InstallerPath. Manual removal is required."
            }
        }
        Write-Output "[+] CrowdStrike Falcon Sensor successfully repaired. Please ensure sensor is checking into the Falcon console."
    } else {
        Write-Output "[+] All checks passed, sensor does not appear to need repair."
    }
}