<# Created by  : Aguilar, Christopher B.
 # E-mail Add  : 
 # Date        : 
 # Description : 
 #>
$ErrorActionPreference = 'Stop'
$Error.Clear()

try {
	Import-Module PoshRSJob -Force -DisableNameChecking
    Join-Path -Path $env:PS_MODULE -ChildPath "PowerOrion.psm1"        | Import-Module -Force
    Join-Path -Path $env:PS_MODULE -ChildPath "PSLogging.psm1"         | Import-Module -Force
    Join-Path -Path $env:PS_MODULE -ChildPath "CommonModules.psm1"     | Import-Module -Force
} catch [Exception] {
    $msg = $_
    if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
    Write-Host "Statistic: -1"
    Write-Host "Message: $msg"
    Exit 1
}

$configXmlFile      = "MonitoreNodeConfig.xml"
$configXPath        = "settings"
$configDbAppSchema  = "NOD"
$configDbEntityName = "GPN"
$configProperties   = @("appDir", 
					    "logRelativeDir", 
                        "key", 
                        "jumpUserName", 
                        "jumpPassword")
$logName            = "MonitoreNode.log"
$hostAndInstance    = "G1NWGSECD001"
$dbName             = "AutomationDB"
$selectMonitoreNode = "CMN.USP_SelectMonitoredNode"
$MaxConcurrentJobs  = 50

function CleanUp-RSJob {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$True)][string]$Batch
	)
	$PollingInterval = 5;
	$CompletedThreads = 0;
	$Status = Get-RSJob -Batch $Batch | Group-Object -Property State;
	$TotalThreads = ($Status | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum;
	while ($CompletedThreads -lt $TotalThreads) {
		$CurrentJobs = Get-RSJob -Batch $Batch;
		$CurrentJobs.Where( { $PSItem.State -eq "Completed" } ) | Remove-RSJob | Out-Null;
		$Status = $CurrentJobs | Group-Object -Property State;
		$CompletedThreads += $Status | Where-Object {$PSItem.Name -eq "Completed"} | Select-Object -ExpandProperty Count;
		Start-Sleep -seconds $PollingInterval;
	}
}

$MonitoreNode = {
	param (
		$hostAndInstance,
		$dbName,
        $jumpCreds,
        $MonitoredNodeId,
        $Domain,
        $Port,
        $Path,
        $IsTlsEncryted,
        $MonitoringLevel
	)

$HttpStatus = {
	param (
		$protocol,
		$domain,
		$port,
		$path,
		$level
	 )
<# Created by  : Aguilar, Christopher B.
 # E-mail Add  : Christopher.Aguilar@globalpay.com
 # Date        : 
 # Description : 
 #>
if (!([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
	
    public class ServerCertificateValidationCallback {
	    public static void Ignore() {
	        ServicePointManager.ServerCertificateValidationCallback += delegate(
                Object obj,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors errors) {
	                return true;
	        };
	    }
	}
"@
}

[ServerCertificateValidationCallback]::Ignore();
#[System.Net.ServicePointManager]::Expect100Continue = $true;
#[System.Net.ServicePointManager]::DefaultConnectionLimit = 9999;
[System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072) -bor [Enum]::ToObject([System.Net.SecurityProtocolType], 768) -bor [Enum]::ToObject([System.Net.SecurityProtocolType], 192) -bor [Enum]::ToObject([System.Net.SecurityProtocolType], 0) -bor [Enum]::ToObject([System.Net.SecurityProtocolType], 48); 

<# Created by  : Aguilar, Christopher B.
	# E-mail Add  : Christopher.Aguilar@globalpay.com
	# Date        : 2021-03-11
	# Description : 
	#>
function Get-ICMPStatus {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True)][string]$domain
		)
	try {
		$pingSender = New-Object System.Net.NetworkInformation.Ping
		$options = New-Object System.Net.NetworkInformation.PingOptions
		$options.DontFragment = $true
		$data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		$buffer = [Text.Encoding]::ASCII.GetBytes($data)
		$timeout = 120;
		$reply = $pingSender.Send($domain, $timeout, $buffer, $options)
		$ret = $reply.Status
	} catch [Exception] { 
        $ret = $($_.Exception.Message).Replace('Exception calling "Send" with "4" argument(s): "', '')
		$ret = $ret.Substring(0,$ret.length-1)
	}
	return $ret
}

<# Created by  : Aguilar, Christopher B.
 # E-mail Add  : Christopher.Aguilar@globalpay.com
 # Date        : 2020-06-09
 # Description : 
 #>
function Testnet {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$True)][string]$domain,
        [Parameter(Mandatory=$True)][int32]$port
	 )
    try { 
        $ret = $(New-Object System.Net.Sockets.TcpClient($domain, $port)).Connected 
    } catch [Exception] { 
        $ret = $($_.Exception.Message).Replace('Exception calling ".ctor" with "2" argument(s): "', '')
		$ret = $ret.Substring(0,$ret.length-1)
    }
    return $ret
}

<# Created by  : Aguilar, Christopher B.
 # E-mail Add  : Christopher.Aguilar@globalpay.com
 # Date        : 2021-03-11
 # Description : 
 #>
function Get-HttpStatus {
    [CmdletBinding()]
	Param (
        [Parameter(Mandatory=$False)][AllowNull()][AllowEmptyString()][string]$protocol = "https",
        [Parameter(Mandatory=$True)][string]$domain,
        [Parameter(Mandatory=$False)][AllowNull()][AllowEmptyString()][string]$port = "443",
        [Parameter(Mandatory=$False)][AllowNull()][AllowEmptyString()][string]$path,
		[Parameter(Mandatory=$False)][AllowNull()][AllowEmptyString()][int]$level = 3 #(1)-ping; (2)-telnet,ping; (3)-http,telnet,ping
	 )

	switch ($level) {
		{ ($_ -in @(1,2,3)) } { 
			$uri = "$($protocol)://$($domain):$($port)"
			if (!(($path -eq $null) -or ($path -eq ""))) { $uri += $path }	
			$http = $(try { $(Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing).StatusCode } catch [Exception] { $_.Exception.Message }) #$_.Exception.Response.StatusCode.value__
			if (!$($($level -ge 3) -and $($http -eq 200))) {
				$telnet = $(try { $(Testnet -domain $domain -port $port) } catch [Exception] { $_.Exception.Message })
				if (!$($($level -ge  2) -and $($telnet -eq $true))) {
					$ping = $(try { $(Get-ICMPStatus -domain $domain) } catch [Exception] { $_.Exception.Message })
					if (!$($($level -ge  1) -and $($ping -eq [System.Net.NetworkInformation.IPStatus]::Success))) {
						return @{-1=$ping.ToString()}
					} elseif ($level -eq  1) {
						return @{1=$ping.ToString()}
					} else {
						return @{-2=$telnet}
					}
				} elseif ($level -eq  2) {
					return @{2=$telnet}
				} else {
					return @{-3=$http}
				}
			} else {
				return @{3=$http}
			}
		} default { 
			return @{0="level out of range"}
		}
	}
}

return Get-HttpStatus -protocol $protocol -domain $domain -port $port -path $path -level $level
} #$HttpStatus
	Join-Path -Path $env:PS_MODULE -ChildPath "CommonModules.psm1" | Import-Module -Force
    if ($IsTlsEncryted) { $protocol = "https" } else { $protocol = "http" }
    $statusJump = $(Invoke-Command -ScriptBlock $HttpStatus -ArgumentList $protocol, $Domain, $Port, $Path, $MonitoringLevel -ComputerName "g1nwgcejmp002.gpn.globalpay.com" -Credential $jumpCreds)
	If ($($statusJump.Keys) -lt 0) { 
		$statusProd = Get-HttpStatus -protocol $protocol -domain $Domain -port $Port -path $Path -level $MonitoringLevel 
		If ($($statusProd.Keys) -lt 0) {
			$statusTool = $(Invoke-Command -ScriptBlock $HttpStatus -ArgumentList $protocol, $Domain, $Port, $Path, $MonitoringLevel -ComputerName "g1nwgtlsw001.gpn.globalpay.com" -Credential $jumpCreds)
			If ($($statusTool.Keys) -lt 0) { 
				if ($($statusJump.Keys) -lt $($statusProd.Keys)) {
					if ($($statusJump.Keys) -lt $($statusTool.Keys)) {
						$status = $statusJump
					} else {
						$status = $statusTool
					}
				} else {
					if ($($statusProd.Keys) -lt $($statusTool.Keys)) {
						$status = $statusProd
					} else {
						$status = $statusTool
					}
				}
			} else {
				$status = $statusTool
			}
		} else {
			$status = $statusProd
		}
	} else {
		$status = $statusJump
	}
	try {
		$con = New-Object System.Data.SqlClient.SqlConnection("Data Source=$hostAndInstance;Initial Catalog=$dbName;Integrated Security=SSPI")
		$con.Open()
		$cmd = New-Object System.Data.SqlClient.SqlCommand("CMN.USP_UpdateMonitoredNode", $con)
		$cmd.CommandType = [System.Data.CommandType]::StoredProcedure
		$cmd.CommandTimeout = 0
		
		$cmd.Parameters.Add("@MonitoredNodeId", [System.Data.SqlDbType]::Int).Direction = [System.Data.ParameterDirection]::Input
		$cmd.Parameters.Item("@MonitoredNodeId").Value = $MonitoredNodeId
		
		$cmd.Parameters.Add("@StatusCode", [System.Data.SqlDbType]::SmallInt).Direction = [System.Data.ParameterDirection]::Input
		$cmd.Parameters.Item("@StatusCode").Value = $($status.Keys)
		
		$cmd.Parameters.Add("@StatusDescription", [System.Data.SqlDbType]::NVarChar, 2000).Direction = [System.Data.ParameterDirection]::Input
		$cmd.Parameters.Item("@StatusDescription").Value = $($status.Values)

		$exec = $cmd.ExecuteNonQuery()
		
		$cmd.Dispose()
		$con.Close()
		$con.Dispose()
	} catch [Exception] { 
		Write-Verbose -Verbose -Message $_
	}
} #$MonitoreNode

switch ($args.Count) {
    1 {
        try {  
            switch ([int]$args.Get(0)) {
                0 { $configValues = Get-ConfigFromXML -xmlFile $configXmlFile -xPath $configXPath }
                1 { $configValues = Get-ConfigFromDB -appSchema $configDbAppSchema -entityName $configDbEntityName -hostAndInstance $hostAndInstance -dbName $dbName }
                default { 
                    $msg = "Invalid command line arguments value."
                    if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
                    Write-Host "Statistic: -1"
                    Write-Host "Message: $msg"
                    Exit 1
                }
            }
            for ($i=0; $i -lt $configProperties.Count; $i++) { if (!$configValues.ContainsKey($configProperties[$i])) { $hasMissingProperty = $True; break; } }
            if (!$hasMissingProperty) {
                $appDir         =                                                                      $configValues.Get_Item($configProperties[0])
                $logRelativeDir =                                                                      $configValues.Get_Item($configProperties[1])
                [Byte[]]$key    =                                                                    $($configValues.Get_Item($configProperties[2])) -split ","
                $jumpUserName   =                                                                      $configValues.Get_Item($configProperties[3])
                $jumpPassword   = $(ConvertFrom-SecureToPlain -SecurePassword $(ConvertTo-SecureString $configValues.Get_Item($configProperties[4]) -Key $key))               
            } else { 
                $msg = "Declared configuration is incomplete."
                if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
                Write-Host "Statistic: -1"
                Write-Host "Message: $msg"
                Exit 1
            }
        } catch [Exception] { 
            $msg = $_
            if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
            Write-Host "Statistic: -1"
            Write-Host "Message: $msg"
            Exit 1
        }
    } default { 
        $msg = "The number of command line arguments does not match the number of values required."
        if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
        Write-Host "Statistic: -1"
        Write-Host "Message: $msg"
        Exit 1
    }    
}

try {
    $logRelativePath = Join-Path -Path $logRelativeDir -ChildPath $logName
    $logFullPath     = Join-Path -Path $appDir -ChildPath $logRelativePath
    $logPath         = $logFullPath | Split-Path -Parent
    if (!$($logPath | Test-Path)) { New-Item -Path $logPath -ItemType Directory | Out-Null }
    if ($($logFullPath | Test-Path)) { if ($([int]$((Get-Item $logFullPath).length/1MB)) -gt 500) { Rename-Item -Path $logFullPath -NewName $($logName + [System.DateTime]::Now.ToString(" yyyy-MM-dd")) } } 
	else { Start-Log -LogPath $logPath -LogName $logName -ScriptVersion "1.0" | Out-Null }
    Write-LogInfo -LogPath $logFullPath -Message "`r`n`r`n[$([DateTime]::Now)]  Script Launched."

	$jumpCreds = $(New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $jumpUserName, $(ConvertTo-SecureString -String $jumpPassword -AsPlainText -Force))
	
    $con = New-Object System.Data.SqlClient.SqlConnection("Data Source=$hostAndInstance;Initial Catalog=$dbName;Integrated Security=SSPI")
    $con.Open()
	$cmd = New-Object System.Data.SqlClient.SqlCommand($selectMonitoreNode, $con)
	$cmd.CommandType = [System.Data.CommandType]::StoredProcedure
	$cmd.CommandTimeout = 0
	
	$adap = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $dtbl = New-Object System.Data.DataTable
	$dtbl.Clear()
	$adap.Fill($dtbl) | Out-Null

	$adap.Dispose()
	$cmd.Dispose()

	$Batch = [System.DateTime]::Now.ToString("yyyyMMddHHmmss")
	if ($dtbl -ne $null) {
		foreach ($rs in $dtbl.Rows) {
			$MonitoredNodeId = $rs.MonitoredNodeId
			$Domain          = $rs.Domain
			$Port            = $rs.Port
			$Path            = $rs.Path
			$IsTlsEncryted   = $rs.IsTlsEncryted
			$MonitoringLevel = $rs.MonitoringLevel
			
			Start-RSJob -ScriptBlock $MonitoreNode -ArgumentList $hostAndInstance, $dbName, $jumpCreds, $MonitoredNodeId, $Domain, $Port, $Path, $IsTlsEncryted, $MonitoringLevel -Batch $Batch -Throttle $MaxConcurrentJobs | Receive-RSJob
		}
	}
	
	CleanUp-RSJob -Batch $Batch

    $msg = "Script runs successfully."
    if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
    Write-Host "Statistic: 0"
    Write-Host "Message: $msg"
    Exit 0
} catch [Exception] { 
    $msg = $_
    if (!(($logFullPath -eq $null) -or ($logFullPath -eq ""))) { Write-LogInfo -LogPath $logFullPath -Message "[$([DateTime]::Now)]  $msg" }
    Write-Host "Statistic: -1"
    Write-Host "Message: $msg"
    Exit 1
}
