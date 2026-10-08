param([switch]$NoBrowser,[switch]$NoRefresh)
$ErrorActionPreference='Stop'
$projectRoot=$PSScriptRoot
$pythonExe=Join-Path $projectRoot '.venv\Scripts\python.exe'
if(!(Test-Path -LiteralPath $pythonExe)){throw 'Run the installation steps in SETUP.md first.'}
$varPath=Join-Path $projectRoot 'var'
New-Item -ItemType Directory -Force -Path $varPath | Out-Null
$pidFile=Join-Path $varPath 'processes.json'
if(Test-Path -LiteralPath $pidFile){throw 'Use Stop-ETIS.ps1 before starting another instance.'}
if(Get-NetTCPConnection -State Listen -LocalPort 8000,5173 -ErrorAction SilentlyContinue){throw 'Port 8000 or 5173 is already in use. Stop the previous instance first.'}
Push-Location $projectRoot
try {
 & $pythonExe scripts/initialize.py
 if($LASTEXITCODE -ne 0){throw 'Database initialization failed.'}
 if(!(Test-Path -LiteralPath (Join-Path $projectRoot 'etis-frontend\dist\index.html'))){throw 'Build the interface using the steps in SETUP.md.'}
 $backendProcess=Start-Process -FilePath $pythonExe -ArgumentList '-m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $varPath 'backend.out.log') -RedirectStandardError (Join-Path $varPath 'backend.err.log')
 $nodeExe=(Get-Command node.exe).Source
 $webProcess=Start-Process -FilePath $nodeExe -ArgumentList 'server.mjs' -WorkingDirectory (Join-Path $projectRoot 'etis-frontend') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $varPath 'web.out.log') -RedirectStandardError (Join-Path $varPath 'web.err.log')
 $records=@(@{id=$backendProcess.Id;kind='backend';exe=$pythonExe},@{id=$webProcess.Id;kind='web';exe=$nodeExe})
 if(!$NoRefresh){
  $workerProcess=Start-Process -FilePath $pythonExe -ArgumentList 'data/scripts/manage_intelligence.py --watch' -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $varPath 'worker.out.log') -RedirectStandardError (Join-Path $varPath 'worker.err.log')
  $records+=@{id=$workerProcess.Id;kind='worker';exe=$pythonExe}
 }
 $records | ConvertTo-Json | Set-Content -LiteralPath $pidFile
 $started=$false
 for($attempt=0;$attempt -lt 30;$attempt++){
  try {
   $live=Invoke-WebRequest 'http://127.0.0.1:8000/health/live' -TimeoutSec 1
   $page=Invoke-WebRequest 'http://127.0.0.1:5173/scan' -TimeoutSec 1
   if($live.StatusCode -eq 200 -and $page.StatusCode -eq 200){$started=$true;break}
  } catch {Start-Sleep -Milliseconds 200}
 }
 if(!$started){& (Join-Path $projectRoot 'Stop-ETIS.ps1');throw 'ETIS did not start. See the logs in var/.'}
 Write-Host 'ETIS started locally: http://127.0.0.1:5173/scan'
 if(!$NoBrowser){Start-Process 'http://127.0.0.1:5173/scan'}
} finally {Pop-Location}
