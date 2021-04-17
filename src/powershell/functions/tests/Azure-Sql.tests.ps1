BeforeAll {
  . (Join-Path (Split-Path -Parent $PSScriptRoot) (Split-Path -Leaf $PSCommandPath).Replace(".tests.", "."))
}

Describe Convert-IgSqlConnectionParamsToServerParams {
  BeforeAll {
    Mock Get-AzSqlServer {
      [PSCustomObject]
      @{
        ResourceGroupName = "my-sql-rg"
      }
    } -ParameterFilter { $ServerName -eq "my-sqlsrv" }

    Mock Get-AzSqlServer { }

    $ConnectionParams = @{
      ServerInstance = "my-sqlsrv.database.windows.net"
      Database       = "my-db"
      Username       = "my-user"
      Password       = "not-your-business"
    }

    $DefaultArguments = @{
      ResourceGroupName = 'my-rg'
      ServerName        = 'my-sqlsrv'
      ConnectionParams  = $ConnectionParams
    }
  }
  It "should return hastable with ServerName" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams @DefaultArguments
    $ServerParams.Keys | Should -Contain 'ServerName'
  }

  It "should return hastable with ResourceGroupName" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams @DefaultArguments
    $ServerParams.Keys | Should -Contain 'ResourceGroupName'
  }

  It "should pass ServerName to result" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams @DefaultArguments
    $ServerParams.ServerName | Should -Be 'my-sqlsrv'
  }

  It "should ResourceGroup to result" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams @DefaultArguments
    $ServerParams.ResourceGroupName | Should -Be 'my-rg'
  }

  It "should call Get-AzSqlServer to get ResourceGroupName" {
    $null = Convert-IgSqlConnectionParamsToServerParams -ConnectionParams $ConnectionParams
    Should -Invoke Get-AzSqlServer
  }

  It "should return ResourceGroupName from Get-AzSqlServer" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams -ConnectionParams $ConnectionParams
    $ServerParams.ResourceGroupName | Should -Be "my-sql-rg"
  }

  It "should return ServerName from ConnectionParams" {
    $ServerParams = Convert-IgSqlConnectionParamsToServerParams -ConnectionParams $ConnectionParams
    $ServerParams.ServerName | Should -Be "my-sqlsrv"
  }

  It "should throw if server not found" {
    { $null = Convert-IgSqlConnectionParamsToServerParams -ServerName 'xxx' -ConnectionParams $ConnectionParams } |
    Should -Throw
  }

  It "should throw if ServerName cannot be determined" {
    $ThisParams = $ConnectionParams.Clone()
    $ThisParams.ServerInstance = $null
    { $null = Convert-IgSqlConnectionParamsToServerParams -ConnectionParams $ThisParams } |
    Should -Throw
  }

}


Describe Remove-IgAzSqlServerFirewallRuleByPattern {

  BeforeAll {
    Mock Get-AzSqlServerFirewallRule { $FirewallRules } -ParameterFilter {
      $ResourceGroupName -eq "my-rg" -and $ServerName -eq "my-sqlsrv"
    }

    Mock Get-AzSqlServerFirewallRule {
      throw "Unexpected call to Get-AzSqlServerFirewallRule with arguments: `n$($Args | Out-String)"
    }

    Mock Remove-AzSqlServerFirewallRule { } -ParameterFilter {
      $ResourceGroupName -eq "my-rg" -and $ServerName -eq "my-sqlsrv" -and $FirewallRuleName -eq 'delete-rule'
    }

    Mock Remove-AzSqlServerFirewallRule {
      throw "Unexpected call to Remove-AzSqlServerFirewallRule with arguments: `n$($Args | Out-String)"
    }

    $ServerParams = @{
      ResourceGroupName = "my-rg"
      ServerName        = "my-sqlsrv"
    }

    # The return result of Get-AzSqlServerFirewallRule mock
    $FirewallRules = $null
  }

  It "should call Get-AzSqlServerFirewallRule to retrieve active firewall rules" {
    Remove-IgAzSqlServerFirewallRuleByPattern @ServerParams -FirewallRuleNamePattern 'abcd'
    Should -Invoke Get-AzSqlServerFirewallRule
  }

  It "should call Remove-AzSqlServerFirewallRule for matching rule" {
    # The return result of Get-AzSqlServerFirewallRule mock
    $FirewallRules = @(
      [PSCustomObject]@{
        FirewallRuleName = 'other-rule'
      },
      [PSCustomObject]@{
        FirewallRuleName = 'delete-rule'
      }
    
    )

    Remove-IgAzSqlServerFirewallRuleByPattern @ServerParams -FirewallRuleNamePattern '^delete'
    Should -Invoke Remove-AzSqlServerFirewallRule
  }

}


Describe Find-IgSqlRequiredFirewallClientIp {

  BeforeAll {

    Mock Invoke-Sqlcmd {} -ParameterFilter { $ServerInstance -eq "connected-sqlsrv" }

    Mock Invoke-Sqlcmd {
      Write-Error "blah blah 10.10.11.12 blah sp_set_firewall_rule blah-blah"
    } -ParameterFilter { $ServerInstance -eq "disconnected-sqlsrv" }

    Mock Invoke-Sqlcmd {
      Write-Error "somebody cannot execute sql command somewhere"
    } -ParameterFilter { $ServerInstance -eq "error-sqlsrv" }

    Mock Invoke-Sqlcmd {
      throw "Unexpected call to Invoke-Sqlcmd with arguments: `n$($Args | Out-String)"
    }
  }

  It "should return false when client can connect" {
    $ConnectionParams = @{
      ServerInstance = "connected-sqlsrv"
    }
    $Result = Find-IgSqlRequiredFirewallClientIp $ConnectionParams
    $Result | Should -Be $false
  }

  It "should return the client IP address from error message when client cannot connect" {
    $ConnectionParams = @{
      ServerInstance = "disconnected-sqlsrv"
    }
    $Result = Find-IgSqlRequiredFirewallClientIp $ConnectionParams
    $Result | Should -Be "10.10.11.12"
  }

  It "should return the client IP address from error message when client cannot connect" {
    $ConnectionParams = @{
      ServerInstance = "error-sqlsrv"
    }
    { $null = Find-IgSqlRequiredFirewallClientIp $ConnectionParams } | Should -Throw
  }
}



Describe Enable-IgSqlFirewallClientAccessRule {
  BeforeAll {
    Mock Find-IgSqlRequiredFirewallClientIp { $false } -ParameterFilter {
      $ConnectionParams.ServerInstance -eq 'connected-sqlsrv'
    }

    Mock Find-IgSqlRequiredFirewallClientIp { '10.11.12.13' } -ParameterFilter {
      $ConnectionParams.ServerInstance -eq 'disconnected-sqlsrv'
    }

    Mock Find-IgSqlRequiredFirewallClientIp {
      throw "Got call to Find-IgSqlRequiredFirewallClientIp with unexpected arguments: `n$($Args | Out-String)"
    }

    Mock New-AzSqlServerFirewallRule { } -ParameterFilter {
      $ServerName -eq 'disconnected-sqlsrv' -and $StartIpAddress -eq '10.11.12.13' -and $EndIpAddress -eq '10.11.12.13' -and $ResourceGroupName -eq 'my-rg'
    }

    Mock New-AzSqlServerFirewallRule {
      throw "Got call to New-AzSqlServerFirewallRule with unexpected arguments: `n$($Args | Out-String)"
    }

    Mock New-Guid { 'guid-here' }

    $ConnectionParamsDisconnected = @{
      ServerInstance = 'disconnected-sqlsrv'
    }

  }

  It "should not do anything when already connected" {
    $ConnectionParams = @{
      ServerInstance = 'connected-sqlsrv'
    }
    Enable-IgSqlFirewallClientAccessRule $ConnectionParams
  }

  It "should invoke New-AzSqlServerFirewallRule when not connected" {
    $null = Enable-IgSqlFirewallClientAccessRule $ConnectionParamsDisconnected -ResourceGroupName 'my-rg'
    Should -Invoke New-AzSqlServerFirewallRule
  }

  It "should create rule with generated name with given prefix" {
    $RuleName = Enable-IgSqlFirewallClientAccessRule $ConnectionParamsDisconnected -ResourceGroupName 'my-rg' -RuleNamePrefix 'tmp-'
    $RuleName | Should -Be 'tmp-guid-here'
  }

  It "should create rule with given name and ignore prefix" {
    $RuleName = Enable-IgSqlFirewallClientAccessRule $ConnectionParamsDisconnected -ResourceGroupName 'my-rg' -RuleName 'extra-rule'
    $RuleName | Should -Be 'extra-rule'
  }

}
