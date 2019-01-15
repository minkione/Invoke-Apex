function Invoke-TimeStomp {
<# 

.SYNOPSIS
	Modifies a files' Creation Time to that of C:\windows\system32\cmd.exe unless "TimeOf" parameter is used.

.PARAMETER Help
	Shows Detailed Help.

.PARAMETER List
	Shows Brief Command Help.

.PARAMETER File
	The file to time stomp. If used without the TimeOf parameter, the timestamp will be changed to that of C:\windows\system32\cmd.exe
	
.PARAMETER TimeOf
	If this parameter is used, it takes the path to another file as an argument, which will be used to set the timestamp for File.

.EXAMPLE 
	PS> Invoke-TimeStomp -File C:\temp\file.exe 
	
.EXAMPLE 
	PS> Invoke-TimeStomp -File C:\temp\file.exe -TimeOf C:\windows\system32\calc.exe
	
.NOTES
	Author: Fabrizio Siciliano (@0rbz_)
#>

[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[Switch]$Help,
	[switch]$List,
	
	[Parameter(Mandatory = $False)]
	[String]$File,
	
	[Parameter(Mandatory = $False)]
	[String]$TimeOf
)

$TimeSource = (Get-Item C:\windows\system32\cmd.exe).FullName

	if ($Help -eq $True) {
		Write @"
		
 ### Invoke-TimeStomp Help ###
 -----------------------------
 |----------------------------------------------------------------------|
 | [-File] file.exe [-TimeOf] someotherfile.exe                         |
 |----------------------------------------------------------------------|

   [*] Description: Modifies a files' Creation Time to that of 
       C:\windows\system32\cmd.exe. The 'TimeOf' parameter can be used
       to change the timestamp to match that of some other file.

   [*] Usage: Invoke-TimeStomp -File C:\temp\file.exe
   [*] Usage: Invoke-TimeStomp -File C:\temp\file.exe -TimeOf C:\windows\system32\calc.exe

   [*] Mitre ATT&CK Ref: T1099 (Timestomp)
   
 \----------------------------------------------------------------------/
 
"@
	}
	elseif ($List -eq $True) {
		Write @"
 
 Invoke-TimeStomp Brief Command List:
 ------------------------------------
 Invoke-TimeStomp -File C:\temp\file.exe
 Invoke-TimeStomp -File C:\temp\file.exe -TimeOf C:\windows\system32\calc.exe
 
"@
	}
	elseif ($File -and $TimeOf) {
	
		$TimeSource = (Get-Item $TimeOf).FullName
		[IO.File]::SetCreationTime("$File", [IO.File]::GetCreationTime($TimeSource))
		[IO.File]::SetLastAccessTime("$File", [IO.File]::GetLastAccessTime($TimeSource))
		[IO.File]::SetLastWriteTIme("$File", [IO.File]::GetLastWriteTime($TimeSource))
		
		Write " `n[+] Changed Creation, Last Access, and Last Write Time for $File`:"
		(Get-Item $File)
	}
	else {

		[IO.File]::SetCreationTime("$File", [IO.File]::GetCreationTime($TimeSource))
		[IO.File]::SetLastAccessTime("$File", [IO.File]::GetLastAccessTime($TimeSource))
		[IO.File]::SetLastWriteTIme("$File", [IO.File]::GetLastWriteTime($TimeSource))
		
		Write " `n[+] Changed Creation, Last Access, and Last Write Time for $File`:"
		(Get-Item $File)
	}
}
