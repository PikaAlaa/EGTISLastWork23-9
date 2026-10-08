$ErrorActionPreference='Stop'
$pidFile=Join-Path $PSScriptRoot 'var\processes.json'
if(!(Test-Path -LiteralPath $pidFile)){Write-Host 'No managed ETIS processes recorded.';exit}
$records=Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
foreach($record in $records){
 $process=Get-Process -Id $record.id -ErrorAction SilentlyContinue
 # Guard against stopping an unrelated process after Windows has reused an ID.
 if($process -and $process.Path -eq $record.exe){
  # The Windows virtual-environment launcher owns a child Python interpreter.
  $children=Get-CimInstance Win32_Process -Filter "ParentProcessId = $($record.id)"
  foreach($child in $children){if($child.Name -eq 'python.exe'){Stop-Process -Id $child.ProcessId -ErrorAction SilentlyContinue}}
  Stop-Process -Id $record.id -ErrorAction SilentlyContinue
 }
}
Remove-Item -LiteralPath $pidFile
Write-Host 'Local ETIS processes stopped.'
