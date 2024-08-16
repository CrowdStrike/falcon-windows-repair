# Falcon Windows Repair

Scripts to help with the diagnosis and repair of unhealthy Windows Falcon sensor installations.

### What's New

#### Release 1.3.1
- Added checks for when a maintenance token would be required.

#### Release 1.3.0
- Removed unnecessary logic when repairing the sensor, reducing API permissions required to run repair script. Added additional commenting to code. 

#### Release 1.2.1
- Added more compatibility checks to ensure script runs properly. Formatted outputted messages/errors. Fixed logic surrounding channel file deletion to avoid possible issues.

#### Release 1.2.0

- Overall improvement to script's checks and logic including formality checks for API ID/secret. Added toggle for Flight Controlled CID's.

#### Release 1.1.0

- New functionality added to enable the repair script to work with Falcon environments where parent-child relationships are used (Flight Control).

#### Initial Release 1.0.0

- Initial release

## Available Scripts

- Get-FalconServiceStatus.ps1 - Checks for common causes of an unhealthy sensor and suggests repair steps
  - Runs locally with no external dependencies
- Repair-FalconSensor.ps1 - Automated script to repair many common issues with a sensor install
  - Requires a properly scoped Falcon API Key and network access
  - Removes 291 Channel Files

## Get-FalconServiceStatus.ps1

Query the current status of the Falcon sensor as installed on the endpoint, and recommend the best repair option given the sensor state.
Additionally, identify whether the defective 291 Channel File(s) remains on disk and requires removal.

### Requirements

- PowerShell 3.0 or higher

### Usage

The script must be run as an administrator on the target machine.

Run with:

`.\Get-FalconServiceStatus.ps1`

## Repair-FalconSensor.ps1

This script attempts to repair broken sensor installs, deletes potential bad 291 channel files, and applies file check logic to only run on systems that have the broken folder / file structure. The script will perform several actions, if the folders/files are found to be changed or altered. **This script is only applicable for hosts that are functioning, where the Falcon Sensor is currently broken, or not reporting to the Falcon Console.**

For machines still stuck within unusable states, please continue to follow instructions outlined in the Tech Alert.

### Requirements

* Falcon Administrator role required to Create API Keys  
  * API Key with following permission:
    * 'Sensor Download: Read'
    * 'Sensor Update Policies: Read + Write'
* 64-bit PowerShell 3.0 or higher  
* TLS 1.2 minimum  
* PowerShell Administrator level execution

### Checks Performed

* Was `C:\Program Files\CrowdStrike\` renamed or deleted?  
* Was `C:\Windows\System32\drivers\CrowdStrike\` renamed or deleted?  
* Was `csagent.sys` renamed or deleted?  
* Was `CsFalconService.exe` renamed or deleted?
* Is the `csagent` service running?
* Is the `CsFalconService` service running?  
* Does the bad ChannelFile exist on disk?

### Script Actions

* Check host for the above issues
* Remove bad ChannelFile if exists  
* Via API, download WindowsSensor to `C:\Temp\`
* Repair the Agent install

### Set-up

1. Generate API Token: [https://falcon.crowdstrike.com/api-clients-and-keys/](https://falcon.crowdstrike.com/api-clients-and-keys/)  
2. Click on `Create API client`, and grant the following permission:
   1. Sensor Download: Read
   2. Sensor Update Policies: Read + Write
3. Copy down the `Client ID` and `Client Secret` from the pop-up.
4. Open `Repair-FalconSensor.ps1` in a text editor
5. Scroll to the “Editable Region” of the script and enter the API `Client ID`, `Client Secret`, your Falcon Cloud, and set Flight Control to `$true` if using this in a Flight Controlled CID.
   1. **NOTE:** These are the ONLY FIELDS THAT SHOULD BE CHANGED IN THE SCRIPT. Nothing else should be altered. 

### Usage

Once Set-up steps are complete, run the script with 

`.\Repair-FalconSensor.ps1`

This script can also be ran by specifying the arguments and values when running

`.\Repair-FalconSensor.ps1 -SourceID {your_ID} -SourceSecret {your_secret} -Cloud {cloud} -FlightControl {$true/$false}`

### Verify Sensor Repair

* **Locally:** Run the following in command line: `sc query csagent`
  * Output for STATE should show: “4 RUNNING”
* **Remote:** Check host `Last Seen` data within host management.
  * It should show a recently updated timestamp if the script was successful.
* **Query / Dashboard:** A fresh run of any of the existing tools used to monitor “DOWN” hosts should reflect repaired hosts now communicating to CrowdStrike, and will be showing as “OKAY”. 