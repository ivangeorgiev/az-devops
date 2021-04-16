BeforeAll {
  . "$PSScriptRoot/../Azure-KeyVault.ps1"
}

Describe ConvertFrom-IgSecureString {
  It 'returns plain text from secure string' {
    $SecureString = ConvertTo-SecureString "hVFkk965BuUv" -AsPlainText -Force
    $PlainText = ConvertFrom-IgSecureString $SecureString

    $PlainText | Should -Be "hVFkk965BuUv"
  }
}

Describe Get-IgAzKeyVaultSecretAsPlainText {

  BeforeEach {
    Mock Get-AzKeyVaultSecret { 
      return @{ SecretValue = ConvertTo-SecureString "hVFkk965BuUv" -AsPlainText -Force } 
    } -ParameterFilter { 
      $KeyVaultName -eq 'key-vault-101' -and $SecretName -eq 'my-secret' 
    }

    Mock Get-AzKeyVaultSecret {
      throw "Get-AzKeyVaultSecret invoked with unexpected parameters KeyVaultName: '$KeyVaultName', SecretName: '$SecretName'"
    }
  }

  It 'retrieves a secret from key vault using Get-AzKeyVaultSecret' {
    
    Get-IgAzKeyVaultSecretAsPlainText -KeyVaultName 'key-vault-101' -SecretName 'my-secret' | Out-Null
    Should -Invoke Get-AzKeyVaultSecret
  }

  It 'converts the secret value to plain text' {
    $SecretPlainText = Get-IgAzKeyVaultSecretAsPlainText -KeyVaultName 'key-vault-101' -SecretName 'my-secret'
    $SecretPlainText | Should -Be "hVFkk965BuUv"
  }
}

