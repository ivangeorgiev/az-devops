<#
.SYNOPSIS
The function returns an OAuth2 access token for the resource specified with URI.

.DESCRIPTION
Obtains and returns an OAuth2 access token for the resource specified with URI.

.OUTPUTS
Token object

.EXAMPLE

```powershell
$KeyVaultName = $Env:KEY_VAULT_NAME

# Application Id and Application Secret are stored in the Key Vault.
$params = @{
    ApplicationId = Get-AzKeyVaultSecretAsPlainText -KeyVaultName $KeyVaultName -SecretName svetlina-01-sp-applicationId
    ApplicationSecret = Get-AzKeyVaultSecretAsPlainText -KeyVaultName $KeyVaultName -SecretName svetlina-01-sp-password
}

# Acquire token
$Token = Get-TokenFromClientCredentials @params -Resource 'https://database.windows.net/'

# Inspect the access token
Write-Host $Token.access_token
```
#>
function Get-TokenFromClientCredentials {
   [cmdletbinding()]
   Param(
      # Optional Tenant ID. If not provided, Tenant ID will be taken from Azure Context.
      [Parameter(Mandatory=$False)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$TenantId,

      # Application Id for which a token is being requested.
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$ApplicationId,

      # Resource URI for which the token is requested unless Scope parameter is specified.
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$ApplicationSecret,

      # Resource ID for which the token is requested. If not specified, Resource parameter is used.
      [Parameter(Mandatory=$False)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [string]$Secret,

      [Parameter(Mandatory=$False)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [string]$Resource  
    )  

    If (-not $TenantId) {
        Write-Verbose "TenantId not specified. Using Get-AzContext"
        $TenantId = (Get-AzContext).Tenant.Id
    }

    If ($Resource -and -not $Scope) {
        If ($Resource.EndsWith("/")) {
            $Scope =  "$Resource" + ".default"
        }
        Else {
            $Scope =  "$Resource" + "/.default"
        }
    }

    $TokenEndpoint = $tokenEndPoint = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $TenantId

    $body = @{
        'scope'         = $Scope
        'client_id'     = $ApplicationId
        'grant_type'    = 'client_credentials'
        'client_secret' = $ApplicationSecret
    }

    $params = @{
        ContentType = 'application/x-www-form-urlencoded'
        Headers     = @{'accept' = 'application/json' }
        Body        = $body
        Method      = 'POST'
        URI         = $TokenEndpoint
    }

    Try {
        $token = Invoke-RestMethod @params
        Return $Token
    }
    Catch {
        Write-Error "Failed to obtain access token for scope '$Scope'. Exception message: $($_.Exception.Message). Error details: $($_.ErrorDetails)"
        Throw
    }
}
