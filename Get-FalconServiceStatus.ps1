<# CrowdStrike Falcon Sensor Status Check
.SYNOPSIS
    Query the current status of the Falcon sensor as installed on the endpoint, and recommend the best repair option given the sensor state. Additionally, identify whether the defective 291 Channel File(s) remains on disk and requires removal.
.EXAMPLE
    .\Get-FalconServiceStatus.ps1
.NOTES
    Version:        v1.1.0
    Author:         CrowdStrike, Inc.
    Creation Date:  25 July 2024
#>

$comparisonEpoch = 1721370420; # The $comparisonEpoch timestamp refers to the end date and time of the impact window: Friday, July 19, 2024 6:27:00 AM UTC 
$csFolderPath = "C:\Program Files\CrowdStrike"; # Path to the CrowdStrike Falcon installation directory
$csDriverFolderPath = "C:\Windows\System32\drivers\CrowdStrike"; # Path to the CrowdStrike Falcon drivers directory
$csAgentFile = "C:\Windows\System32\drivers\CrowdStrike\csagent.sys"; # Path to the primary CrowdStrike Falcon Sensor driver
$csServiceFile = "C:\Program Files\CrowdStrike\CsFalconService.exe"; # Path to the primary CrowdStrike Falcon service binary

# Check if the CrowdStrike Program Files directory exists on disk with the correct name and set variables for LastWriteTimeUtc and Epoch time conversion for later use
if(Test-Path $csFolderPath) {
    $csFolderExists = $True;
    $csFolderTime = Get-Item -Path $csFolderPath -EA 0 | Select-Object -ExpandProperty LastWriteTimeUtc;
    $csFolderTimeEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $csFolderTime).TotalSeconds)
} else {
    $csFolderExists = $False;
};

# Check if the CrowdStrike drivers directory exists on disk with the correct name and set variables for use in later checks
if(Test-Path $csDriverFolderPath) {
    $csDriverFolderExists = $True;
} else {
    $csDriverFolderExists = $False;
};

# Define variables for Falcon agent service names
$svcName1 = "CsFalconService";
$svcName2 = "csagent";

# Query the Falcon services and assing to variables
$serviceInfo1 = Get-Service -Name $svcName1;
$serviceInfo2 = Get-Service -Name $svcName2;

# Assign variables whether the Falcon services are running or not
if ($serviceInfo1.Status -ne "Running") {
    $csfStatus = $False;
    Write-Output "[!] '$($svcName1)' service is NOT running."
} else {
    $csfStatus = $True;
    Write-Output "[+] '$($svcName1)' service is running."
};
if ($serviceInfo2.Status -ne "Running") {
    $csaStatus = $False;
    Write-Output "[!] '$($svcName2)' service is NOT running."
} else {
    $csaStatus = $True;
    Write-Output "[+] '$($svcName2)' service is running."
};

# Logic for checking the status of both Falcon services, followed by whether the Falcon directories have been modified, renamed or deleted. Depending on the scenario, the output provides the recommended approach to repairing the sensor
if($csfStatus -and $csaStatus) {
    $sensorStateOK = $True;
    Write-Output "[+] The CrowdStrike Falcon sensor services are running normally."
} elseif (($csFolderExists) -and -Not($csfStatus) -and ($csaStatus)) {
    Write-Output "[!] The CrowdStrike Falcon 'Program Files' folder was likely modified. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
} elseif (-Not($csFolderExists) -and -Not($csfStatus) -and ($csaStatus)) {
    Write-Output "[!] The CrowdStrike Falcon 'Program Files' folder was likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
} elseif (-Not($csfStatus) -and -Not($csaStatus)) {
    if (-Not($csFolderExists) -and -Not($csDriverFolderExists)) {
        Write-Output "[!] The CrowdStrike Falcon 'C:\Program Files\CrowdStrike' and 'C:\Windows\System32\drivers\CrowdStrike' folders were likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
    } elseif (($csFolderExists) -and -Not($csDriverFolderExists)) {
        if($csFolderTimeEpoch -gt $comparisonEpoch) {
            Write-Output "[!] The CrowdStrike Falcon 'C:\Windows\System32\drivers\CrowdStrike' folder was likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> /repair /silent /forcedowngrade /norestart'"
        } else {
            Write-Output "[!] The CrowdStrike Falcon 'Program Files' folder was likely renamed or modified. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
        }
    } elseif (($csFolderExists) -and ($csDriverFolderExists)) {
        if(-Not(Test-Path $csAgentFile) -and -Not(Test-Path $csServiceFile)) {
            Write-Output "[!] The CrowdStrike Falcon 'C:\Windows\System32\drivers\CrowdStrike\csagent.sys' and 'C:\Program Files\CrowdStrike\CsFalconService.exe' files were likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
        } elseif (-Not(Test-Path $csAgentFile) -and (Test-Path $csServiceFile)) {
            Write-Output "[!] The CrowdStrike Falcon 'C:\Windows\System32\drivers\CrowdStrike\csagent.sys' file was likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> /repair /silent /forcedowngrade /norestart'"
        } elseif ($csFolderTimeEpoch -gt $comparisonEpoch) {
            Write-Output "[!] The CrowdStrike Falcon 'Program Files' folder was likely renamed or modified. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> MAINTENANCE_TOKEN=<maintenance token> /repair /silent /forcedowngrade /norestart'"
        }
    }
} elseif (($csfStatus) -and -Not($csaStatus)) {
    if(-Not(Test-Path $csAgentFile)) {
        Write-Output "[!] The CrowdStrike Falcon 'C:\Windows\System32\drivers\CrowdStrike\csagent.sys' file was likely renamed or deleted. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> /repair /silent /forcedowngrade /norestart'"
    } else {
        Write-Output "[!] The CrowdStrike Falcon 'C:\Windows\System32\drivers\CrowdStrike' folder was likely modified. Repair the sensor by placing the respective sensor version installer binary in 'C:\Temp\' and running the following command: 'C:\Temp\<installation_file.exe> /repair /silent /forcedowngrade /norestart'"
    }
};

# Check for the impacted ChannelFile on disk and provide recommedation whether to delete it or not
$impactedChannelFiles = Get-ChildItem -Path "C:\Windows\System32\drivers\CrowdStrike\C-00000291*.sys" -EA 0;
if($null -ne $impactedChannelFiles) {
    ForEach ($channelFile in $impactedChannelFiles) {
        $channelFileTimeEpoch = [int][double]::Parse((New-TimeSpan -Start ([datetime]'1970-01-01 00:00:00') -End $channelFile.LastWriteTimeUtc).TotalSeconds)
        if($channelFileTimeEpoch -gt $comparisonEpoch) {
            if(-Not($sensorStateOK)) {
                Write-Output "[+] Channel File '$($channelFile.FullName)' is likely NOT impacted. Proceed with sensor repair."
            }
        } else {
            Write-Output "[!] Channel File '$($channelFile.FullName)' is likely impacted. DELETE '$($channelFile.FullName)' prior to repairing the sensor to avoid any potential BSOD crashes after repair."            
        }
    }
}
