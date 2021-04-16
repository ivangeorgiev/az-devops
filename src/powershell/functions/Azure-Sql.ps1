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
try {
    # Use Ensure-SqlFirewallClientAccessRule to make sure firewall rule
    # allowing client connection is in place.
    $NewRuleName = Ensure-SqlFirewallClientAccessRule -ConnectionParams $ConnectionParams -RuleNamePrefix "deploy-" -Verbose

    # Do something in the database
    Invoke-SqlCmd @ConnectionParams -Query "SELECT getdate()"
} finally {
    # In case firewall rule was created, remove it
    if ($NewRuleName) {
        $ServerParams = Detect-AzSqlServerFromConnectionParams $ConnectionParams -Verbose
        Remove-AzSqlServerFirewallRule @ServerParams -FirewallRuleName $NewRuleName
    }
}
```

#>
function Ensure-SqlFirewallClientAccessRule {
    [cmdletbinding()]
    param(
        # Sql connection parameters to pass to Invoke-SqlCmd.
        [Parameter(Mandatory = $true, Position = 0)][ValidateNotNull()][ValidateNotNullOrEmpty()]
        [hashtable]$ConnectionParams,

        # Optional firewall rule name. If not provided, new rule name is generated using the RuleNamePrefix parameter and New-Guid
        [Parameter(Mandatory = $false)]
        [string]$RuleName,

        # Optional firewall rule name prefix to be added to the generated rule name.
        [Parameter(Mandatory = $false)]
        [string]$RuleNamePrefix,

        # Optional Resource Group Name.
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName,
        
        # Optional Sql Server resource name
        [Parameter(Mandatory = $false)]
        [string]$ServerName
    )

    $RequiredClientIp = Detect-SqlRequiredFirewallClientIp -ConnectionParams $ConnectionParams
    if (-not $RequiredClientIp) {
        Write-Verbose "Client connects Ok. Seems client can connect."
        Return $False
    }

    $ServerParams = Detect-AzSqlServerFromConnectionParams -ConnectionParams $ConnectionParams -ResourceGroupName $ResourceGroupName -ServerName $ServerName

    if (-not $RuleName) {
        $RuleName = "$RuleNamePrefix$(New-Guid)"
        Write-Verbose "RuleName not provided. Generated rule name is: $RuleName"
    }

    $StartIp = $RequiredClientIp
    $EndIp = $RequiredClientIp

    Write-Verbose "Adding new firewall rule $RuleName to $ResourceGroupName/$ServerName for range $StartIp - $EndIp"

    $Output = New-AzSqlServerFirewallRule @ServerParams -FirewallRuleName $RuleName -StartIpAddress $StartIp -EndIpAddress $EndIp
    Return $RuleName
}


<#
.SYNOPSIS
Find Sql Server details from connection parameters.

.DESCRIPTION
Find Sql Server details from connection parameters.

.OUTPUTS
Sql Server details hashtable

.EXAMPLE

```powershell
$ConnectionParams = @{
    ServerInstance = "$($Env:DB_SERVER).database.windows.net"
    Database = $Env:DB_DATABASE
    Username = $Env:DB_USERNAME
    Password = $Env:DB_PASSWORD
}

$ServerParams = Detect-AzSqlServerFromConnectionParams $ConnectionParams -Verbose
Remove-AzSqlServerFirewallRule @ServerParams -FirewallRuleName $NewRuleName
```

#>
function Detect-AzSqlServerFromConnectionParams {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][ValidateNotNull()][ValidateNotNullOrEmpty()]
        [hashtable]$ConnectionParams,

        # Optional Resource Group Name. If not provided, the result from Get-SqlServer is used.
        [Parameter(Mandatory = $false)]
        [string]$ResourceGroupName,

        # Optinal Server Name. If not provided, the ServerInstance connection parameter is used.
        [Parameter(Mandatory = $false)]
        [string]$ServerName
    )
    if (-not $ServerName) {
        $ServerName = $ConnectionParams.ServerInstance.Split('.')[0]
        Write-Verbose "ServerName not provided, using ConnectionParams.ServerInstance."
        if (-not $ServerName) {
            Throw "ServerName not provided. Trying to use ConnectionParams.ServerInstance also did not return result."
        }
        Write-Verbose "ServerName found: $ServerName"
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

    $ServerDetails = @{
        ResourceGroupName = $ResourceGroupName
        ServerName = $ServerName
    }

    Return $ServerDetails
}
<#
.SYNOPSIS
Remove Azure Sql Server firewall rules with names matching given pattern.

.DESCRIPTION
Remove Azure Sql Server firewall rules with names matching given pattern.

.EXAMPLE


```powershell
# Regular expression for matching GUID string
$GuidPattern = "([0-9a-z]{8})(-[0-9a-z]{4}){3}-([0-9a-z]{12})"

# Firewall rule name prefix
$RuleNamePrefix = "deploy-"

# Database connection parameters for Invoke-SqlCmd
$ConnectionParams = @{
    ServerInstance = "$($Env:DB_SERVER).database.windows.net"
    Database = $Env:DB_DATABASE
    Username = $Env:DB_USERNAME
    Password = $Env:DB_PASSWORD
}

# Get Sql Server parameters from the connection paramters
$ServerParams = Detect-AzSqlServerFromConnectionParams $ConnectionParams -Verbose

# Add firewall rule
$NewRuleName = Ensure-SqlFirewallClientAccessRule -ConnectionParams $ConnectionParams -RuleNamePrefix $RuleNamePrefix -Verbose

# Verify current rules
Get-AzSqlServerFirewallRule @ServerParams

# Do some work
Invoke-Sqlcmd @ConnectionParams -Query "SELECT getdate()"

# Remove firewall rules which start with the given prefix, followed by a GUID
Remove-AzSqlServerFirewallRuleByPattern @ServerParams -FirewallRuleNamePattern "^${RuleNamePrefix}${GuidPattern}`$" -Verbose

```

#>

function Remove-AzSqlServerFirewallRuleByPattern {
    [cmdletbinding()]
    param(
        # Resource Group Name
        [string]$ResourceGroupName,
        # Azure Sql Server name - FQDN or resource name.
        [string]$ServerName,
        # Pattern to match
        [string]$FirewallRuleNamePattern
    )

    $Rules = Get-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName

    $RuleNameMatchRegex = New-Object -TypeName System.Text.RegularExpressions.Regex -ArgumentList $FirewallRuleNamePattern

    $Rules | ForEach {
        if ($RuleNameMatchRegex.IsMatch($_.FirewallRuleName)) {
            Write-Verbose "Remove rule $($_.FirewallRuleName)"
            $Result = Remove-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $ServerName -FirewallRuleName $_.FirewallRuleName
        }
    }
}

