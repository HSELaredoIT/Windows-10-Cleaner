Write-Output "`n" # New Line for separation
$temp = $env:TEMP
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

"{0, 10}: {1}" -f "Timestamp", (Get-Date -Format "yyyy-MM-dd HH:mm tt")
"{0, 10}: {1}" -f "Computer", $env:COMPUTERNAME
"{0, 10}: {1}" -f "User", "$env:USERNAME"

$AppList = @(

    "*Weather*",
    "*zune*",
    "*Solitaire*",
    "*MicrosoftOfficeHub*",
    "*Skype*",
    "*Feedback*",
    "*Onenote*",
    "*Phone*",
    "*Wallet*",
    "*Getstarted*"

)

foreach ($App in $AppList) {

    Get-AppxPackage -Name $App | ForEach-Object {"Removing: $($_.PackageFullName)"}
    Get-AppxPackage -Name $App | Remove-AppxPackage
	Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like $App} | Remove-AppxProvisionedPackage -Online

}

#Win10 - Disable Advertising

New-item -Path HKLM:\Software\Policies\Microsoft\Windows -Name CloudContent -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableSoftLanding -Value 1 -Type DWord -Force                # Don't show Windows Tips
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Value 1 -Type DWord -Force    # Disable Windows Consumer Features

#Remove Suggested Apps
reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
Set-ItemProperty -Path Registry::HKU\Default_User\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
reg unload HKU\Default_User

#Remove Pinned Suggested Apps
Invoke-WebRequest "https://gitea.popcornrules.com/POPCORNrules/Windows-10-Cleaner/raw/branch/master/DefaultLayout.xml" -OutFile "$temp\DefaultLayout.xml"
Import-StartLayout -LayoutPath "$temp\DefaultLayout.xml" -MountPath "C:\"
