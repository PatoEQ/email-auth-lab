# Punto de entrada en Windows (PowerShell): .\lab.ps1 <comando>
# Ejecuta la CLI `lab` dentro de la toolbox, en la red aislada del laboratorio.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$labArgs = if ($args.Count -eq 0) { @('--help') } else { $args }

docker compose run --rm toolbox lab @labArgs
exit $LASTEXITCODE
