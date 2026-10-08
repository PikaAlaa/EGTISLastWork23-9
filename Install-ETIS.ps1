param([switch]$Start,[switch]$TrainCandidates)
$ErrorActionPreference='Stop'
$projectRoot=$PSScriptRoot
Push-Location $projectRoot
try {
 $pythonExe=Join-Path $projectRoot '.venv\Scripts\python.exe'
 if(!(Test-Path -LiteralPath $pythonExe)){
  if(Get-Command uv.exe -ErrorAction SilentlyContinue){& uv.exe venv --python 3.12 .venv}
  else {& py.exe -3.12 -m venv .venv}
  if($LASTEXITCODE -ne 0){throw 'Python 3.12 is required. See SETUP.md.'}
 }
 $requirementsFile=if($TrainCandidates){'requirements-models.txt'}else{'requirements-runtime.txt'}
 if(Get-Command uv.exe -ErrorAction SilentlyContinue){& uv.exe pip install --python $pythonExe -r $requirementsFile}
 else {& $pythonExe -m pip install -r $requirementsFile}
 if($LASTEXITCODE -ne 0){throw 'Dependency installation failed.'}
 & $pythonExe scripts/initialize.py
 if($LASTEXITCODE -ne 0){throw 'Database initialization failed.'}
 if($TrainCandidates){
  & $pythonExe data/scripts/rebuild_dataset.py --augment-synthetic
  if($LASTEXITCODE -ne 0){throw 'Dataset rebuild failed.'}
  foreach($trainer in @('ml/train_character_model.py','ml/train_bilstm_candidate.py','ml/train_lightgbm_candidate.py')){
   & $pythonExe $trainer
   if($LASTEXITCODE -ne 0){throw "Training failed: $trainer"}
  }
  & $pythonExe ml/select_model.py --apply-local
  if($LASTEXITCODE -ne 0){throw 'Model selection failed.'}
 }
 Push-Location (Join-Path $projectRoot 'etis-frontend')
 try {
  & npm.cmd ci --no-audit --no-fund
  if($LASTEXITCODE -ne 0){throw 'Interface dependency installation failed.'}
  & npm.cmd run build
  if($LASTEXITCODE -ne 0){throw 'Interface build failed.'}
 } finally {Pop-Location}
 Write-Host 'ETIS installed. Local secrets are in the ignored .env file.'
 if($Start){& (Join-Path $projectRoot 'Start-ETIS.ps1')}
} finally {Pop-Location}
