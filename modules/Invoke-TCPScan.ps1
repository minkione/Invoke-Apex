function Invoke-TCPScan {
<#

.SYNOPSIS
    Simple TCP Port Scanner.

.PARAMETER Help
    Shows Detailed Help.

.PARAMETER List
    Shows Brief Command Help.

.PARAMETER IpAddress
    Ip Address to Scan.

.PARAMETER Ports
    A comma separated list of ports to scan.

.EXAMPLE
    PS> Invoke-TCPScan -IpAddress 192.168.0.1 -Ports 80,443,8080

.NOTES 
	Author: Fabrizio Siciliano (@0rbz_)
#>

[CmdletBinding()]
param (
    [Parameter(Position=1)]
    [Switch]$Help,
    [switch]$List,

    [Parameter(Mandatory = $False)]
    [String]$IpAddress,
    $Ports
)

    if ($Help -eq $true) {
        Write @"

 ### Invoke-TCPScan Help ###
 ---------------------------
 Available Invoke-TCPScan Commands:
 ----------------------------------
 |---------------------------------------------------------------------|
 | [-IpAddress] ip_address [-Ports] ports                              |
 |---------------------------------------------------------------------|

   [*] Description: Simple TCP Port Scanner.

   [*] Usage: Invoke-TCPScan -IpAddress 192.168.0.1 -Ports 80,443,8080

   [*] Mitre ATT&CK Ref: T1423 (Network Service Scanning)

 \---------------------------------------------------------------------/

"@
    }
    elseif ($List -eq $True) {
        Write @"

 Invoke-TCPScan Brief Command List:
 ----------------------------------
 Invoke-TCPScan -IpAddress 192.168.0.1 -Ports 80,443,8080

"@
    }
    elseif ($IpAddress) {
        if ($PSVersionTable.PSVersion.Major -eq "2") {
            Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
            return
        }
        $ping = (Test-Connection -Quiet -Count 1 $IpAddress)
#       $ping = $true
        if ($Ping) {

            foreach ($Port in $Ports) {
                $TcpClient = New-Object System.Net.Sockets.TcpClient
                $Connect = $TcpClient.BeginConnect($IpAddress, $Port, $Null, $Null)
                $TimeOut = $Connect.AsyncWaitHandle.WaitOne(1, $False)

                if (!$TimeOut) {
                    $TcpClient.Close()
                    sleep 1
                }
                else {
                    Write "Open: $Port"
                    $TcpClient.Close()
                    sleep 1
                }
            }
        }
        else {
            Write "Host Appears Offline."
        }
    }
}
