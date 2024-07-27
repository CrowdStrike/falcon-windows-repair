<#
    .SYNOPSIS 
        PS v3 or higher required
        TLS 1.2 required
    .NOTES
    Version:   v1.1.0
    Author:    CrowdStrike, Inc.
    Usage:      Use at your own risk. While all efforts have been made to ensure this script works as expected, you should test
                in your own environment. 
    Requirements:    
    Falcon Administrator role required for Created API access
    API Key with following permissions: 'Hosts: Read', 'Sensor Download: Read', 'Sensor Update Policies: Read/Write'
    PowerShell v3 or higher
    TLS 1.2 minimum
    Sign the script, or execute with bypass        
    .DESCRIPTION
        Determines state of Falcon Sensor and repairs as necessary. Additional checks for bad channel file are performed, and file 
        is removed if deemed bad.
    .PARAMETER SourceId
        OAuth2 API Client Id from the source tenant.  
    .PARAMETER SourceSecret
        OAuth2 API Client Secret from the source tenant.
    .PARAMETER Cloud
        Falcon Cloud to utilize. Available options: 'us-1', 'us-2', 'eu-1', 'us-gov-1'  
#>


<# -------------------      Begin Editable Region. -------------- #>
[CmdletBinding()]
param( 

    [Parameter(Mandatory = $false)]
    [string]$SourceId = '',
 
    [Parameter(Mandatory = $false)]
    [string]$SourceSecret = '',

    [ValidateSet('eu-1', 'us-1', 'us-2', 'us-gov-1')]
    [string]$Cloud = ''



)
<# ----------------      END Editable Region. ----------------- #>










begin {
    if ($PSVersionTable.PSVersion -lt '3.0')
       { throw "This script requires a miniumum PowerShell 3.0" }
    if (!([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')) {
        if (([enum]::GetNames([Net.SecurityProtocolType]) -contains [Net.SecurityProtocolType]::Tls12)) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } else {
            throw "Unable to use Tls12. Please review .NET and PowerShell requirenments."
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
            throw "The term '$($cmd)' is not recognized as the name of a cmdlet."
        }
    }
} 
process {
    $repairHost = $false
    $remediationEpoch = 1721370420
    $csFolderPath = "C:\Program Files\CrowdStrike"
    $csDriverFolderPath = "C:\Windows\System32\drivers\CrowdStrike"
    $InstallerPath = 'C:\temp\WindowsSensor.exe'
    $Hash = ''
    $InstallArgs = '/repair /quiet /norestart /forcedowngrade ProvNoWait=1'
    $tempFolderCreated = $false
    try {
        if (-not (Test-Path $csFolderPath) -or -not (Test-Path $csDriverFolderPath)) {
            $repairHost = $true
        } else {
            $csFolderTime = Get-Item -Path $csFolderPath | Select-Object -ExpandProperty LastWriteTimeUtc;
            $csFolderTimeEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csFolderTime).TotalSeconds)
            $csDriverFolderPath = Get-Item -Path $csDriverFolderPath | Select-Object -ExpandProperty LastWriteTimeUtc;
            $csDriverFolderPathEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csDriverFolderPath).TotalSeconds)
            if (($csFolderTimeEpoch -gt $remediationEpoch) -or ($csDriverFolderPathEpoch -gt $remediationEpoch)) {
                $repairHost = $true
            }
        }
        if (((Get-Service -Name "CsFalconService").Status -ne "Running") -or ((Get-Service -Name "CsFalconService").Status -ne "Running")) {
            $repairHost = $true
        }
        if (-not (Test-Path "C:\Windows\System32\drivers\CrowdStrike\csagent.sys") -or -not (Test-Path "C:\Program Files\CrowdStrike\CsFalconService.exe")) {
            $repairHost = $true
        }   
    } catch {
        $repairHost = $true
    }    
    try {
        $channelFiles = Get-ChildItem "C:\Windows\System32\drivers\CrowdStrike\C-00000291*.sys" -Filter $fileFilter
        foreach ($cf in $channelFiles) {
            # Get file creation time of channel file
            $fileCreationTime = (Get-Item "$($cf.FullName)").CreationTime
            $fileCreationEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $fileCreationTime).TotalSeconds)
            if ($fileCreationEpoch -lt $remediationEpoch) {
                # Remove the file if file creation epoch is less (earlier) than comparison epoch
                Remove-Item -Path "$($cf.FullName)" -Force -ErrorAction Stop
            }
        } 
    } catch {
            continue
    }     
    if ($repairHost) {
        # Validate if API credentials have been set.
        if ((-not $SourceId) -or (-not $SourceSecret)) {
            throw "API credentials not configured properly"
        }
        if (-not (Test-Path -Path "C:\temp\")) {
            New-Item -Path "C:\" -Name "temp" -ItemType "directory"
            $tempFolderCreated = $true
        }
        $Retries=0
        do {
            if (-not $Cloud) {
                throw "Cloud not specified, please specify -Cloud in arguments."
            }
            switch ($Cloud) {
                'eu-1' { $SrcHostname = 'https://api.eu-1.crowdstrike.com' }
                'us-1' { $SrcHostname = 'https://api.crowdstrike.com' }
                'us-2' { $SrcHostname = 'https://api.us-2.crowdstrike.com' }
                'us-gov-1' { $SrcHostname = 'https://api.laggar.gcw.crowdstrike.com' }
            }
            $Param = @{
                Uri = "$($SrcHostname)/oauth2/token"
                Method = 'post'
                Headers = @{
                    accept = 'application/json'
                    'content-type' = 'application/x-www-form-urlencoded'
                }
                Body = @{
                    'client_id' = $SourceId
                    'client_secret' = $SourceSecret
                }
            }    
            # Get API Token
            $SrcToken = try {(Invoke-WebRequest @Param -UseBasicParsing -MaximumRedirection 0)
                        } catch {
                            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                                Write-Output $_.ErrorDetails.Length
                                $_.ErrorDetails | ConvertFrom-Json
                            } elseif ($_.Exception.Response) {
                                if ($_.Exception.Response.StatusCode -eq 403) {
                                    throw "Unable to request token from source cloud $($Cloud) using client id $($SourceId) due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review source API credentials."
                                }
                            } else {
                                $_.Exception
                            }
                        }    
            if ($SrcToken.StatusCode -ne 201) {
                if (!$SrcToken.Headers) {
                    Write-Host "Unable to request token. Please check API credentials or connectivity. Current response is: $($SrcToken)"
                    break
                } else {
                    $Cloud=$SrcToken.Headers.'X-Cs-Region'
                }
            }
            $Retries++
        } while ($SrcToken.StatusCode -ne 201 -and $Retries -le 4)    
        $SrcToken = ($SrcToken | ConvertFrom-Json)    
        if (-not $SrcToken.access_token) {
            throw "Unable to request token from source cloud $($Cloud) using client id $($SourceId). Return was: $($SrcToken)"
        }              
        $Param = @{
            Uri = "$($SrcHostname)/policy/combined/sensor-update/v2?filter=platform_name%3A%20%27Windows%27%2Bname%3A%20%27platform_default%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
            }
        }
        # Get Host Id from registry
        $HostId = ''
        if (Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default") -Name AG -ErrorAction SilentlyContinue) {
            $HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CrowdStrike\" +
                        "{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}" +
                        "\Default") -Name AG -ErrorAction SilentlyContinue).AG)).ToLower() -replace '-','')
        } elseif (Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue) {
            $HostId = ([System.BitConverter]::ToString(((Get-ItemProperty ("HKLM:\SYSTEM\CurrentControlSet\Services" +
                        "\CSAgent\Sim") -Name AG -ErrorAction SilentlyContinue).AG)).ToLower() -replace '-','')
        }
        $Param = @{
            Uri = "$($SrcHostname)/devices/entities/devices/v2?ids=$($HostId)"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
            }
        }
        # Obtain sensor version of host
        $agentVersion = try {
            (((Invoke-WebRequest @Param -UseBasicParsing) | ConvertFrom-Json).resources.agent_version)
        }
        catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                Write-Output $_.ErrorDetails.Length
                $_.ErrorDetails | ConvertFrom-Json
            } elseif ($_.Exception.Response) {
                if ($_.Exception.Response.StatusCode -eq 403) {
                    throw "Unable to determine hash to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor update policies scope for client id $($SourceId) with read permission or set sensor hash manually."
                }
            } else {
                $_.Exception
            }
        }
        $agentVersion = ($agentVersion.Split(".")[0..2]) -join '.'
        $Param = @{
            Uri = "$($SrcHostname)/policy/combined/sensor-update/v2?filter=platform_name%3A%20%27Windows%27%2Bname%3A%20%27platform_default%27"
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
                authorization = "$($SrcToken.token_type) $($SrcToken.access_token)"
            }
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
                    throw "Unable to determine hash to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($SourceId) or set sensor hash manually."
                }
            } else {
                $_.Exception
            }
        }
        # Compare hash from build versions found, and agent version on host
        foreach ($findBuild in $Installers.resources) {
            if ($findBuild.version -eq $agentVersion) {
                $Hash = $findBuild.sha256
                break
            }
        }
        if (-not $Hash) {
            throw "Unable to determine installation package hash to be used in this process."
        }        
        if (Test-Path $InstallerPath) {
            if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
                Remove-Item $InstallerPath
            }
        }    
        if ((Test-Path $InstallerPath) -eq $false) {
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
            $Request = try {
                Invoke-WebRequest @Param -UseBasicParsing
            }
    
            catch {
                if ($_.ErrorDetails -and $_.ErrorDetails.Length -gt 1) {
                    Write-Output $_.ErrorDetails.Length
                    $_.ErrorDetails | ConvertFrom-Json
                } elseif ($_.Exception.Response) {
                    if ($_.Exception.Response.StatusCode -eq 403) {
                        throw "Unable to download sensor file to be used due to error $([int] $_.Exception.Response.StatusCode): $($_.Exception.Response.StatusDescription). Please review Sensor Download scope for client id $($SourceId) or upload sensor file manually at $($InstallerPath)."
                    }
                } else {
                    $_.Exception
                }
            }
    
            if ((Test-Path $InstallerPath) -eq $false) {
                throw "Unable to locate $($InstallerPath)"
            }
            if ((Get-FileHash $InstallerPath).Hash.ToUpper() -ne $Hash.ToUpper()) {
                throw "$($InstallerPath) hash differs. File looks like corrupted."
            }
        }    
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
        # Get sensor maintenance token
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
            throw "Unable to retrieve uninstall token from source cloud $($Cloud) using client id $($SourceId). Return was: $($Request)"
        }
        $InstallArgs += " MAINTENANCE_TOKEN=$($Request.resources.uninstall_token)"
        Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgs -PassThru | ForEach-Object {
            Write-Output "[$($_.Id)] '$($_.ProcessName)' beginning recover; sensor will become unresponsive..."
            Write-Output "[$($_.Id)] Beginning recover using the following arguments: '$($InstallArgs)' ..."
        }
        try {
            if (-not (Test-Path $csFolderPath) -or -not (Test-Path $csDriverFolderPath)) {
                throw "Error occured while repairing CrowdStrike Falcon"
            } 
            if (((Get-Service -Name "CsFalconService").Status -ne "Running") -or ((Get-Service -Name "CsFalconService").Status -ne "Running")) {
                throw "Error occured while repairing CrowdStrike Falcon"
            }        
        } catch {
            throw "Error occured while repairing CrowdStrike Falcon"
        } 
        try {
            if ($tempFolderCreated) {
                Remove-Item -Path "C:\Temp\" -Force -Recurse
            } else {
                Remove-Item -Path "C:\Temp\WindowsSensor.exe"
            }
        } catch {
            throw "Not able to clean up installer."
        }
    }
}
