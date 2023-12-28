@echo off

set TEST_SCR_DIR=%~dp0
cd %TEST_SCR_DIR%
set TEST_SCR_PATH=%TEST_SCR_DIR%inet-chk-simple-powershell.ps1

IF EXIST "%TEST_SCR_PATH%" (
    echo Running test script
    where pwsh.exe >nul 2>&1
    IF not errorlevel 1 (
        pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%TEST_SCR_PATH%"
    ) ELSE (
        echo Running on legacy PowerShell. This may not work some tests.
        powershell -NoProfile -ExecutionPolicy Bypass -File "%TEST_SCR_PATH%"
    )
) ELSE (
    color 0c
    echo There are no test script
)