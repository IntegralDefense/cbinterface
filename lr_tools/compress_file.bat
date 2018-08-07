@echo off
set arg1=%1
set dirpath=%1
set host=%computername%

:: should be run from C:\

cd "C:\Windows\CarbonBlack"

:: zip up templrdir
if not exist "C:\Windows\CarbonBlack\tempdir" mkdir C:\Windows\CarbonBlack\tempdir
move %arg1% tempdir
echo $source = "C:\Windows\CarbonBlack\tempdir" >> _zipIt.ps1
echo $destination = "C:\Windows\CarbonBlack\_memdump.zip" >> _zipIt.ps1
echo Add-Type -assembly "system.io.compression.filesystem" >> _zipIt.ps1
echo [io.compression.zipfile]::CreateFromDirectory($source, $destination) >> _zipIt.ps1


powershell.exe -executionpolicy bypass -File _zipIt.ps1

:: If the powershell runtime environ on the host is on at least 4.5 then
:: the system.io.compression.filesystem will fail and the zip will not
:: exist - this is why  we delete the origional dump file only if 
:: the zip exists. This way, the analyst can still collect the full
:: memdump if compression failed
if exist "C:\Windows\CarbonBlack\_memdump.zip" (
    DEL %arg1%
) ELSE (
    move tempdir\%arg1% %arg1%
)
:: cleanup
@RD /S /Q tempdir
DEL _zipIt.ps1

