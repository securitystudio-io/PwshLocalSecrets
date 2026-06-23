Add-Type -AssemblyName System.Security

$script:PrivateStore = Join-Path $HOME '.private'
$script:Scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser

function _EnsureStore {
    if (-not (Test-Path $script:PrivateStore)) {
        New-Item -ItemType Directory -Path $script:PrivateStore -Force | Out-Null
    }
}

function _SecretPath([string]$Name) {
    Join-Path $script:PrivateStore "$Name.json"
}

function _Encrypt([string]$PlainText) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $script:Scope)
    [Convert]::ToBase64String($encrypted)
}

function _Decrypt([string]$CipherText) {
    $bytes = [Convert]::FromBase64String($CipherText)
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $script:Scope)
    [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Get-xSecret {
    <#
    .SYNOPSIS
        Retrieves a DPAPI-encrypted secret from the private store.
    .DESCRIPTION
        Reads and decrypts a secret stored under ~/.private/<Name>.json using the
        Windows Data Protection API (DPAPI). Only the Windows user who encrypted
        the file can decrypt it.

        By default the full deserialized object is returned. Use -Value to pluck a
        single property, or -AsCredential to get a PSCredential object.
    .PARAMETER Name
        The name of the secret. Maps to the file ~/.private/<Name>.json.
    .PARAMETER Value
        Name of a single property to return from the secret object.
    .PARAMETER AsCredential
        Return a PSCredential object built from the secret's username and password
        properties. Use -UserProp and -PassProp to override which properties are used.
    .PARAMETER UserProp
        Property name to read as the credential username. Defaults to 'Username'.
        Only applies when -AsCredential is specified.
    .PARAMETER PassProp
        Property name to read as the credential password. Defaults to 'Password'.
        Only applies when -AsCredential is specified.
    .EXAMPLE
        Get-xSecret -Name TestSecret

        Returns the full decrypted object for the secret named TestSecret.
    .EXAMPLE
        Get-xSecret -Name TestSecret -Value Username

        Returns only the value of the Username property from TestSecret.
    .EXAMPLE
        Get-xSecret -Name TestSecret -AsCredential

        Returns a PSCredential using the default Username and Password properties.
    .EXAMPLE
        Get-xSecret -Name TestSecret -AsCredential -UserProp User -PassProp Pass

        Returns a PSCredential using custom property names User and Pass.
    .EXAMPLE
        $cred = Get-xSecret -Name MyServer -AsCredential
        Invoke-Command -ComputerName myserver -Credential $cred -ScriptBlock { hostname }

        Retrieves a credential and passes it directly to Invoke-Command.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1, ParameterSetName = 'Object')]
        [string]$Value,

        [Parameter(Mandatory, ParameterSetName = 'Credential')]
        [switch]$AsCredential,

        [Parameter(ParameterSetName = 'Credential')]
        [string]$UserProp = 'Username',

        [Parameter(ParameterSetName = 'Credential')]
        [string]$PassProp = 'Password'
    )

    $path = _SecretPath $Name
    if (-not (Test-Path $path)) {
        Write-Error "Secret '$Name' not found at '$path'."
        return
    }

    $cipherText = Get-Content -Path $path -Raw
    $json = _Decrypt $cipherText.Trim()
    $secret = $json | ConvertFrom-Json

    if ($AsCredential) {
        $userVal = $secret.PSObject.Properties[$UserProp]
        $passVal = $secret.PSObject.Properties[$PassProp]
        if ($null -eq $userVal) {
            Write-Error "UserProp '$UserProp' does not exist on secret '$Name'."
            return
        }
        if ($null -eq $passVal) {
            Write-Error "PassProp '$PassProp' does not exist on secret '$Name'."
            return
        }
        $securePass = ConvertTo-SecureString -String $passVal.Value -AsPlainText -Force
        return [System.Management.Automation.PSCredential]::new($userVal.Value, $securePass)
    }

    if ($PSBoundParameters.ContainsKey('Value')) {
        $prop = $secret.PSObject.Properties[$Value]
        if ($null -eq $prop) {
            Write-Error "Property '$Value' does not exist on secret '$Name'."
            return
        }
        return $prop.Value
    }

    return $secret
}

function New-xSecret {
    <#
    .SYNOPSIS
        Returns a generic secret schema object ready to populate and pass to Add-xSecret.
    .DESCRIPTION
        Creates a PSCustomObject with the default schema fields: Name, Username, Password,
        Url, and Notes. Fill in the properties and pipe the result to Add-xSecret.

        You are not required to use this schema — Add-xSecret accepts any object or
        hashtable with any property names.
    .EXAMPLE
        $s = New-xSecret
        $s.Name     = 'MyService'
        $s.Username = 'admin'
        $s.Password = 'hunter2'
        $s | Add-xSecret -Name MyService

        Creates a new secret using the default schema and saves it to the store.
    .EXAMPLE
        $custom = [PSCustomObject]@{ User = 'admin'; Pass = 'secret'; Token = 'abc123' }
        Add-xSecret -Name ApiToken -Secret $custom

        Stores a custom-schema secret without using New-xSecret.
    #>
    [CmdletBinding()]
    param()

    [PSCustomObject]@{
        Name     = ''
        Username = ''
        Password = ''
        Url      = ''
        Notes    = ''
    }
}

function Add-xSecret {
    <#
    .SYNOPSIS
        Encrypts and stores a secret object in ~/.private/<Name>.json.
    .DESCRIPTION
        Serializes the provided object to JSON, encrypts it with DPAPI (CurrentUser scope),
        and writes the result to ~/.private/<Name>.json. The ~/.private/ directory is
        created automatically if it does not exist.

        Use -Overwrite to replace an existing secret. Without it, the command errors
        if the file already exists.
    .PARAMETER Name
        The key name for the secret. The file will be saved as ~/.private/<Name>.json.
    .PARAMETER Secret
        The object or hashtable to encrypt and store. Accepts pipeline input.
        Any object that serializes cleanly with ConvertTo-Json is supported.
    .PARAMETER Overwrite
        Replace an existing secret with the same name. Without this switch the
        command writes an error if the file already exists.
    .EXAMPLE
        $s = New-xSecret
        $s.Username = 'admin'
        $s.Password = 'hunter2'
        Add-xSecret -Name MyService -Secret $s

        Saves a new secret named MyService to the private store.
    .EXAMPLE
        $s | Add-xSecret -Name MyService

        Pipes a secret object to Add-xSecret.
    .EXAMPLE
        Add-xSecret -Name MyService -Secret $updatedSecret -Overwrite

        Replaces an existing MyService secret with new values.
    .EXAMPLE
        Add-xSecret -Name ApiToken -Secret @{ Token = 'abc123'; Endpoint = 'https://api.example.com' }

        Stores a hashtable as a secret — no New-xSecret required.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [object]$Secret,

        [switch]$Overwrite
    )

    _EnsureStore

    $path = _SecretPath $Name
    if ((Test-Path $path) -and -not $Overwrite) {
        Write-Error "Secret '$Name' already exists. Use -Overwrite to replace it."
        return
    }

    if ($PSCmdlet.ShouldProcess($path, 'Encrypt and write secret')) {
        $json = $Secret | ConvertTo-Json -Depth 10
        $cipherText = _Encrypt $json
        Set-Content -Path $path -Value $cipherText -Encoding UTF8 -NoNewline
        Write-Verbose "Secret '$Name' encrypted and saved to '$path'."
    }
}

function Remove-xSecret {
    <#
    .SYNOPSIS
        Removes a secret from the private store.
    .DESCRIPTION
        Permanently deletes the encrypted file ~/.private/<Name>.json. This action
        cannot be undone. The command prompts for confirmation by default due to its
        high impact; use -Confirm:$false to suppress the prompt in scripts.
    .PARAMETER Name
        The name of the secret to delete. Must match an existing file in ~/.private/.
    .EXAMPLE
        Remove-xSecret -Name TestSecret

        Prompts for confirmation, then deletes ~/.private/TestSecret.json.
    .EXAMPLE
        Remove-xSecret -Name TestSecret -Confirm:$false

        Deletes the secret without prompting — useful in automated scripts.
    .EXAMPLE
        Remove-xSecret -Name TestSecret -WhatIf

        Shows what would be deleted without actually removing the file.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name
    )

    $path = _SecretPath $Name
    if (-not (Test-Path $path)) {
        Write-Error "Secret '$Name' not found at '$path'."
        return
    }

    if ($PSCmdlet.ShouldProcess($path, 'Delete secret')) {
        Remove-Item -Path $path -Force
        Write-Verbose "Secret '$Name' removed."
    }
}

Export-ModuleMember -Function Get-xSecret, New-xSecret, Add-xSecret, Remove-xSecret
