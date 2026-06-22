# xSecret

A PowerShell module for managing secrets stored as DPAPI-encrypted JSON files in your user profile.

Secrets are encrypted using the [Windows Data Protection API (DPAPI)](https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) under `CurrentUser` scope — only the Windows account that encrypted a secret can decrypt it, on the same machine. No keys to manage, no external dependencies.

Files are stored at `~/.private/<Name>.json`.

---

## Installation

Copy the `xSecret` folder to a directory on your `$PSModulePath`, or import directly:

```powershell
Import-Module "C:\path\to\xSecret\xSecret.psm1"
```

To load automatically in every session, add the import to your `$PROFILE`.

---

## Commands

| Command | Description |
|---|---|
| `New-xSecret` | Returns a blank secret object with the default schema |
| `Add-xSecret` | Encrypts and saves a secret to `~/.private/` |
| `Get-xSecret` | Retrieves and decrypts a secret |
| `Remove-xSecret` | Permanently deletes a secret |

---

## Usage

### Create and save a secret

```powershell
$s = New-xSecret
$s.Name     = 'MyService'
$s.Username = 'admin'
$s.Password = 'hunter2'
$s.Url      = 'https://myservice.example.com'
$s.Notes    = 'Production account'

Add-xSecret -Name MyService -Secret $s
```

The default schema includes `Name`, `Username`, `Password`, `Url`, and `Notes`. You can also use any custom object or hashtable — the schema is not enforced.

```powershell
# Custom schema
$custom = [PSCustomObject]@{ Token = 'abc123'; Endpoint = 'https://api.example.com' }
Add-xSecret -Name MyApiToken -Secret $custom

# Hashtable
Add-xSecret -Name MyApiToken -Secret @{ Token = 'abc123'; Endpoint = 'https://api.example.com' }
```

### Retrieve a secret

```powershell
# Full decrypted object
Get-xSecret -Name MyService

# Single property value
Get-xSecret -Name MyService -Value Username

# As a PSCredential (uses Username and Password properties by default)
$cred = Get-xSecret -Name MyService -AsCredential

# As a PSCredential with custom property names
$cred = Get-xSecret -Name MyApiToken -AsCredential -UserProp User -PassProp Pass
```

### Use a credential directly

```powershell
$cred = Get-xSecret -Name MyServer -AsCredential
Invoke-Command -ComputerName myserver -Credential $cred -ScriptBlock { hostname }
```

### Update an existing secret

```powershell
$s = Get-xSecret -Name MyService
$s.Password = 'correcthorsebatterystaple'
Add-xSecret -Name MyService -Secret $s -Overwrite
```

### Remove a secret

```powershell
# Prompts for confirmation
Remove-xSecret -Name MyService

# Skip confirmation (for scripts)
Remove-xSecret -Name MyService -Confirm:$false

# Preview without deleting
Remove-xSecret -Name MyService -WhatIf
```

---

## Security notes

- Encryption uses **DPAPI `CurrentUser` scope** — the secret is bound to your Windows user account and machine. Copying the file to another machine or user account renders it unreadable.
- The `~/.private/` directory is created automatically. You may want to verify its permissions (`icacls "$HOME\.private"`) to ensure other local accounts cannot read the ciphertext files.
- Secrets are decrypted in memory only for the duration of the call — no plaintext is written to disk.

---

## Command reference

### `New-xSecret`

Returns a `PSCustomObject` with the default schema fields pre-populated as empty strings.

```
New-xSecret
```

### `Add-xSecret`

```
Add-xSecret [-Name] <String> [-Secret] <Object> [-Overwrite] [-WhatIf]
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Name` | String | Yes | Key name for the secret; becomes the filename |
| `-Secret` | Object | Yes | Any object or hashtable to encrypt and store |
| `-Overwrite` | Switch | No | Replace an existing secret with the same name |

### `Get-xSecret`

```
Get-xSecret [-Name] <String> [[-Value] <String>]

Get-xSecret [-Name] <String> -AsCredential [-UserProp <String>] [-PassProp <String>]
```

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-Name` | String | Yes | | Name of the secret to retrieve |
| `-Value` | String | No | | Return only this property's value |
| `-AsCredential` | Switch | No | | Return a `PSCredential` object |
| `-UserProp` | String | No | `Username` | Property to use as the credential username |
| `-PassProp` | String | No | `Password` | Property to use as the credential password |

`-Value` and `-AsCredential` are mutually exclusive.

### `Remove-xSecret`

```
Remove-xSecret [-Name] <String> [-Confirm:$false] [-WhatIf]
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Name` | String | Yes | Name of the secret to delete |

Prompts for confirmation by default (`ConfirmImpact = High`). Pass `-Confirm:$false` to suppress in scripts.
