param (
    [string]$Computers
)

$computerNames = Get-Content -Path $Computers

$scriptBlock = {
    function Uninstall-TeamsClassic($TeamsPath) {
        try {
            $process = Start-Process -FilePath "$TeamsPath\Update.exe" -ArgumentList "--uninstall /s" -PassThru -Wait -ErrorAction STOP
    
            if ($process.ExitCode -ne 0) {
                Write-Error "Uninstallation failed with exit code $($process.ExitCode)."
            }
        }
        catch {
            Write-Error $_.Exception.Message
        }
    }

    # Remove Teams Machine-Wide Installer
    Write-Host "Removing Teams Machine-wide Installer"
    ## Get all subkeys and match the subkey that contains "Teams Machine-Wide Installer" DisplayName.
    $registryPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $MachineWide = Get-ItemProperty -Path $registryPath | Where-Object -Property DisplayName -eq "Teams Machine-Wide Installer"

    if ($MachineWide) {
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x ""$($MachineWide.PSChildName)"" /qn" -NoNewWindow -Wait
    }
    else {
        Write-Host "Teams Machine-Wide Installer not found"
    }

    # Lots of modified code blocks from https://www.pdq.com/blog/modifying-the-registry-users-powershell/#powershell-script-to-modify-the-registry-for-all-users

    # Regex pattern for user SIDs
    $patternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'

    # Get Username, SID, and location of ntuser.dat for all users using HKLM Profile List
    $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $patternSID} | 
    Select-Object @{name="SID";expression={$_.PSChildName}}, 
            @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
            @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
    
    # Get list of users with loaded hives in HKU and compare against profileList to get users with unloaded hives
    $loadedUserHives = Get-ChildItem Registry::HKEY_USERS | Where-Object {$_.PSChildName -match $patternSID} | Select-Object @{name="SID";expression={$_.PSChildName}}
    $unloadedUserHives = Compare-Object $profileList.SID $loadedUserHives.SID | Select-Object @{name="SID";expression={$_.InputObject}}, UserHive, Username

    foreach ($User in $profileList) {
        if ($User.SID -in $unloadedUserHives.SID) {
            reg load HKU\$($User.SID) $($User.UserHive) | Out-Null
        }
        Write-Host "  Processing user: $($User.Username)"
        # Write-Host "  User SID: $($User.SID)"

        # Two possible locations for Classic Teams install
        $localAppData = "$($ENV:SystemDrive)\Users\$($User.Username)\AppData\Local\Microsoft\Teams"
        $programData = "$($env:ProgramData)\$($User.Username)\Microsoft\Teams"

        # Classic Teams should only be in one of these paths, or not in either
        if (Test-Path "$localAppData\Current\Teams.exe") {
            Write-Host "    Uninstall Teams for user $($User.Username)"
            Uninstall-TeamsClassic -TeamsPath $localAppData
        }
        elseif (Test-Path "$programData\Current\Teams.exe") {
            Write-Host "    Uninstall Teams for user $($User.Username)"
            Uninstall-TeamsClassic -TeamsPath $programData
        }
        else {
            Write-Host "    Teams installation not found for user $($User.Username)"
        }
        
        # Uninstall string for Classic Teams orphans associated registry keys, need to manually remove
        if (Test-Path -Path "Registry::HKEY_USERS\$($User.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams") {
            Remove-Item "Registry::HKEY_USERS\$($User.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams" -Recurse -Force
            Write-Host "    Successfully removed Classic Teams registry keys for user $($User.Username)"
        } else {
            Write-Host "    Could not find Classic Teams registry keys for user $($User.Username)"
        }

        # Unload ntuser.dat for users that are not currently logged in
        if ($User.SID -in $unloadedUserHives.SID) {
            [gc]::Collect()
            reg unload HKU\$($User.SID) | Out-Null
        }
    }

    # Remove old Teams folders and icons
    $TeamsFolder_old = "$($ENV:SystemDrive)\Users\*\AppData\Local\Microsoft\Teams"
    $TeamsIcon_old = "$($ENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
    Get-Item $TeamsFolder_old | Remove-Item -Force -Recurse
    Get-Item $TeamsIcon_old | Remove-Item -Force -Recurse
}

foreach ($computer in $computerNames) {
    try {
        Write-Host "Working on computer: {$computer}"
        Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock
    } catch {
        Write-Host "Failed to connect to {$computer}"
    }
}