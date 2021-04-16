<#
.SYNOPSIS
The function determines if the client is able to reach Sql Server.

.DESCRIPTION
The function is trying to connect to Sql Server and run a simple query.
If the operation is successful, the return result is True. 
Otherwise the function returns the client IP address if it was detected
or False if the client IP address was not detected.

.OUTPUTS
True, the client IP address or False.

.EXAMPLE

```powershell
$ConnectionParams = @{
    ServerInstance = "$($Env:DB_SERVER).database.windows.net"
    Database = $Env:DB_DATABASE
    Username = $Env:DB_USERNAME
    Password = $Env:DB_PASSWORD
}

Detect-SqlRequiredFirewallClientIp -ConnectionParams $ConnectionParams -Verbose

```

#>
function Detect-SqlRequiredFirewallClientIp {
    [cmdletbinding()]
    param(
        $ConnectionParams
    )

    try {
        Write-Verbose "Trying to reach SQL server"
        $query = 'SELECT getdate() AS THE_DATE'
        $output = (Invoke-Sqlcmd @ConnectionParams -Query $query -ErrorVariable errors -ErrorAction SilentlyContinue ) | Out-String
        if ($output.Contains('THE_DATE') -eq $true) {
            Return $false
        }
    } catch {
        Write-Verbose "Failed to reach SQL server. $($_.Exception.Message)"
        $ErrorMessage = ($errors | Out-String)
    }

    if ($errors.Count -le 0) {
        
        Return $false
    }

    $message = $errors[0].ToString()
    $pattern = "([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)"
    $regex = New-Object -TypeName System.Text.RegularExpressions.Regex -ArgumentList $pattern

    if ($message.Contains("sp_set_firewall_rule") -eq $true -and $regex.IsMatch($message) -eq $true) {
        $IpAddress = $regex.match($message).Groups[0].Value
        Return $IpAddress
    } else {
        Throw "Failed to detect client IP address. Error message contains no sp_set_firewall_rule and ip address: $ErrorMessage"
    }
}


<#
.SYNOPSIS
Make sure Sql Server firewall rule to allow client connection is in place.

.DESCRIPTION
Detect if client can connect to Sql Server and add firewall rule if not.

.OUTPUTS
The new firewall rule name or $false if no rule was created.

.EXAMPLE

```powershell
$ConnectionParams = @{
    ServerInstance = "$($Env:DB_SERVER).database.windows.net"
    Database = $Env:DB_DATABASE
    Username = $Env:DB_USERNAME
    Password = $Env:DB_PASSWORD
}

Ensure-SqlFirewallClientAccessRule -ConnectionParams $ConnectionParams -RuleNamePrefix "deploy-" -Verbose

```

#>
function Ensure-SqlFirewallClientAccessRule {
    [cmdletbinding()]
    param(
        $ConnectionParams,
        $RuleName,
        $RuleNamePrefix,
        $ResourceGroupName,
        $ServerName
    )

    $RequiredClientIp = Detect-SqlRequiredFirewallClientIp -ConnectionParams $ConnectionParams
    if (-not $RequiredClientIp) {
        Write-Verbose "Client connects Ok. Seems client can connect."
        Return $False
    }

    if (-not $ServerName) {
        $ServerName = $ConnectionParams.ServerInstance.Split('.')[0]
        Write-Verbose "ServerName not provided, using ConnectionParams.ServerInstance: $ServerName"
        if (-not $ServerName) {
            Throw "ServerName not provided. Trying to use ConnectionParams.ServerInstance also did not return result."
        }
    }

    if (-not $ResourceGroupName) {
        Write-Verbose "ResourceGroupName not provided. Trying to use Get-AzSqlServer."
        $SqlServer = (Get-AzSqlServer -ServerName $ServerName)
        if (-not $SqlServer) {
            Throw "Failed to get Sql Server $ServerName. Get-AzSqlServer returned empty result."
        }
        $ResourceGroupName = $SqlServer.ResourceGroupName
        Write-Verbose "ResourceGroupName found: $ResourceGroupName"
    }

    if (-not $RuleName) {
        $RuleName = "$RuleNamePrefix$(New-Guid)"
        Write-Verbose "RuleName not provided. Generated rule name is: $RuleName"
    }

    $StartIp = $RequiredClientIp
    $EndIp = $RequiredClientIp

    Write-Verbose "Adding new firewall rule $RuleName to $ResourceGroupName/$ServerName for range $StartIp - $EndIp"

    $Output = New-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -FirewallRuleName $RuleName -StartIpAddress $StartIp -EndIpAddress $EndIp
    Return $RuleName
}



