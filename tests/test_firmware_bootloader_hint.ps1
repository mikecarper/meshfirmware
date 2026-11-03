$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$file = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware.cmd'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "firmware.cmd parse failed: $($parseErrors -join '; ')" }
$function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-MeshCoreBootloaderHintText' }, $true)
if (-not $function) { throw 'Bootloader hint function missing' }
Invoke-Expression $function.Extent.Text

function Get-MeshCoreDeviceConfigEntry { param($hw) return $script:device }
$hardware = [pscustomobject]@{}
$script:device = [pscustomobject]@{ bootloader = @('https://example.test/xiao_nrf52840_ble_bootloader.uf2') }
$hint = Get-MeshCoreBootloaderHintText -hw $hardware
if ($hint -notmatch 'XIAO Sense' -or $hint -match 'Recommended bootloader file') { throw "XIAO base image was recommended without identifying the board: $hint" }
$script:device = [pscustomobject]@{ bootloader = @('https://example.test/xiao_nrf52840_ble_sense_bootloader.zip') }
$hint = Get-MeshCoreBootloaderHintText -hw $hardware
if ($hint -notmatch 'XIAO Sense' -or $hint -match 'Recommended bootloader file') { throw "XIAO Sense hint was not identity-aware: $hint" }
$script:device = [pscustomobject]@{ bootloader = @('https://example.test/heltec_t114.zip') }
$hint = Get-MeshCoreBootloaderHintText -hw $hardware
if ($hint -notmatch 'Recommended bootloader file: https://example.test/heltec_t114.zip') { throw "Unrelated board hint changed: $hint" }
Write-Host 'PASS: bootloader hints avoid guessing XIAO module identity'
