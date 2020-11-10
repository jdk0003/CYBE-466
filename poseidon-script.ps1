Get-WindowsFeature AD-Domain-Services | Install-WindowsFeature
Import-Module addsdeployment
Install-ADDSForest
Install-WindowsFeature DHCP -IncludeManagementTools
netsh dhcp add securitygroups
Restart-Service dhcpserver
Add-DHCPServerv4Scope -Name “DHCP Range” -StartRange 192.168.101.10 -EndRange 192.168.101.20 -SubnetMask 255.255.255.0 -State Active
Set-DHCPServerv4Scope -ScopeID 192.168.101.0 -LeaseDuration 1:00:00:00
Set-DHCPServerv4OptionValue -ScopeID 192.168.101.0 -DNSDomain jdk0003.internal -DNSServer 192.168.101.4 -Router 192.168.101.1
Add-DHCPServerInDC -DNSName poseidon.jdk0003.internal -IPAddress 192.168.101.4
Restart-Service dhcpserver
Add-DHCPServerv4Reservation -ScopeID 192.168.101.0 -IPAddress 192.168.101.3 -ClientID “52:4B:55:39:D0:66” -Description “Hades”
Add-DHCPServerv4Reservation -ScopeID 192.168.101.0 -IPAddress 192.168.101.2 -ClientID “06:3D:2E:6A:C2:86” -Description “Zeus”
Add-DHCPServerv4Reservation -ScopeID 192.168.101.0 -IPAddress 192.168.101.5 -ClientID “D6:02:BC:E5:AD:CD” -Description “Apollo”
Restart-Service dhcpserver
Add-DNSServerForwarder -IPAddress 157.182.203.110 -PassThru
Add-DNSServerPrimaryZone -Name jdk0003.internal -Zonefile "jdk0003.internal.dns"
Add-DNSServerResourceRecordA -Name “zeus.jdk0003.internal” -ZoneName “jdk0003.internal” -IPv4Address “192.168.101.2” -TimeToLive 01:00:00
Add-DNSServerResourceRecordA -Name “hades.jdk0003.internal” -ZoneName “jdk0003.internal” -IPv4Address “192.168.101.3” -TimeToLive 01:00:00
Add-DNSServerResourceRecordA -Name “poseidon.jdk0003.internal” -ZoneName “jdk0003.internal” -IPv4Address “192.168.101.4” -TimeToLive 01:00:00
Add-DNSServerResourceRecordA -Name “apollo.jdk0003.internal” -ZoneName “jdk0003.internal” -IPv4Address “192.168.101.5” -TimeToLive 01:00:00
Add-DNSServerResourceRecordCNAME -HostNameAlias hades.jdk0003.internal -Name www -ZoneName jdk0003.internal
mkdir C:\inetpub\wwwroot\serve
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
New-WebVirtualDirectory -Site “Default Web Site” -Name Serve -PhysicalPath C:\inetpub\wwwroot\serve
New-ADUser -Name “cybe466grader” -GivenName cybe466 -Surname grader -SamAccountName cybe466grader -UserPrincipalName cybe466grader@jdk0003.internal
Set-ADAccountPassword “CN=cybe466grader,CN=users,DC=jdk0003,DC=internal” -Reset -NewPassword (ConvertTo-SecureString -AsPlainText “Cyb3rs3curity” -Force)
Enable-ADAccount -Identity cybe466grader
ADD-ADGroupMember “Domain Admins” cybe466grader
Rename-Computer -NewName "poseidon"
Reboot
