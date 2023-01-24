<#
Andy Morales

.DESCRIPTION
This script reconstructs GOOTLOADER payloads from the regsitry.

Legal Notice

Copyright 2023 Mandiant.  All Rights Reserved

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

.NOTES
In order to reconstruct the payload of a different user, the variables $RegistryPayloadPath and $Username must be modified.

.PARAMETER User
Specify this parameter in order to run the script against another user that is currently logged in.

.EXAMPLE
GootloaderWindowsRegDecode.ps1

Run script against the current user.

.EXAMPLE
GootloaderWindowsRegDecode.ps1 -User JSmith

Run script against the user JSmith.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, position = 1)]
    [string]$User
)

$PayloadPath = 'Software\microsoft\Phone\'

Function Invoke-RegToString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        $RegKey
    )
    
    for ($i=0; $i -le 714;$i++){
        Try{
            $RegData+=$RegKey.$i
        }
        Catch{
        }
    }
    
    Return $RegData
}

Function Save-Payload {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        $PayloadData,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$OutputName
    )
    
    Set-Content $OutputName -Value $PayloadData -Encoding Byte
    
    Write-Output "File: $($OutputName)`nMD5: $((Get-FileHash -Path $OutputName -Algorithm MD5).hash)`n"   
}

#region setPaths
if([string]::IsNullOrEmpty($User)){
    $RegistryPayloadPath = 'Registry::HKEY_CURRENT_USER\' + $PayloadPath
    $Username = [Environment]::username

    Write-Output "Retrieving the registry payload from the current user account. `n"
}
else{
    
    $objUser = New-Object System.Security.Principal.NTAccount($User)

    $OtherUserSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])

    $RegistryPayloadPath = 'Registry::HKEY_USERS\' + $OtherUserSID.Value + '\' + $PayloadPath
    $Username = $User
    
    Write-Output "Retrieving the payload of a different user requires running the script as Administrator. `n"
}
#endregion

#region payload1
$userPhoneKey0 = Get-ItemProperty -path ($RegistryPayloadPath+$Username+"0");

$payload1data = Invoke-RegToString -RegKey $userPhoneKey0

<#
$g=0;
while($true){
	$g++;
	$mathResult=[math]::("sqrt")($g);
	if($mathResult -eq 1000){
		break
	}
}
#>

#mathResult is always going to be 1000 so skip the middle man...
$mathResult = 1000

$p1ReplacedText=$payload1data.replace("#",$mathResult);

$payload1ByteArray=[byte[]]::("new")($p1ReplacedText.Length/2);

for($e=0; $e -lt $p1ReplacedText.Length;$e+=2){
	$payload1ByteArray[$e/2]=[convert]::("ToByte")($p1ReplacedText.Substring($e,2),(2*8))
}
	

Save-Payload -PayloadData $payload1ByteArray -OutputName "payload1.dll_"
#endregion

#region payload2
$userPhoneKey = Get-ItemProperty -Path ($RegistryPayloadPath+$Username);

$payload2data = Invoke-RegToString -RegKey $userPhoneKey

$p2replacedText = $payload2data.replace("q","000").replace("v","0").replace("w","1").replace("r","2").replace("t","3").replace("y","4").replace("u","5").replace("i","6").replace("o","7").replace("p","8").replace("s","9").replace("q","A").replace("h","B").replace("j","C").replace("k","D").replace("l","E").replace("z","F")

$payload2ByteArray = [byte[]] -split ($p2replacedText -replace '..', '0x$& ')

Save-Payload -PayloadData $payload2ByteArray -OutputName "payload2.exe_"
#endregion
