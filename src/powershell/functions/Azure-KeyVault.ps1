<#
.SYNOPSIS
The function returns a Key Vault secret value as plain text.

.DESCRIPTION
Retrieves and returns a Key Vault secret value as plain text.

.OUTPUTS
Secret plain text

.ExAMPLE

```powershell
$KeyVaultName = $Env:KEY_VAULT_NAME

Get-AzKeyVaultSecretAsPlainText -KeyVaultName $KeyVaultName -SecretName dcata01sqldb-writer
```
#>
function Get-IgAzKeyVaultSecretAsPlainText {
   Param(
      # Key Vault Name
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$KeyVaultName,

      # Secret Name for to be retrieved from the Key Vault.
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$SecretName
   )  

   $Secret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName)
   $SecretValueText = ConvertFrom-IgSecureString $Secret.SecretValue

   return $secretValueText
}


<#
.SYNOPSIS
Convert secure string to plain text.

.DESCRIPTION
Convert secure string to plain text.

.OUTPUTS
String
   Plain text

.ExAMPLE
$SecureString = ConvertTo-SecureString "hVFkk965BuUv" -AsPlainText -Force
ConvertFrom-IgSecureString $SecureString

#>
function ConvertFrom-IgSecureString {
   param(
      # Secret string to convert to plain text
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [System.Security.SecureString]$SecureString
   )
   $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
   try {
      $SecretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
   }
   finally {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
   }
   return $SecretValueText
}
