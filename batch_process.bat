@echo off
set INPUT_DIR=C:\research\lolcandidates\Temp
set IDA_PATH=C:\Program Files\IDA Essential 9.0
set SCRIPT=C:\tools\idascripts\lolbas.py

for %%F in (%INPUT_DIR%\*.exe) do (
    "%IDA_PATH%\ida.exe" -B -S"%SCRIPT%" "%%F"
)
