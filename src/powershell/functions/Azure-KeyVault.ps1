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
function Get-AzKeyVaultSecretAsPlainText {
   Param(
      # Key Vault Name
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$KeyVaultName,

      # Secret Name for to be retrieved from the Key Vault.
      [Parameter(Mandatory)][ValidateNotNull()][ValidateNotNullOrEmpty()]  
      [String]$SecretName
    )  

    $Secret = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName)

    # This construct is needed for Windows PowerShell. In PowerShell 7+ ConvertFrom-SecureString could be used
    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
    try {
       $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
    } finally {
       [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
    }
    return $secretValueText
}
