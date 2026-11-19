@echo off
rem Startet die Defender Performance Analyzer GUI mit Windows PowerShell 5.1
cd /d "%~dp0"

rem Falls die Datei beim Download als .ps1.txt gespeichert wurde, korrigieren
if not exist "%~dp0DefenderPerfAnalyzer-GUI.ps1" if exist "%~dp0DefenderPerfAnalyzer-GUI.ps1.txt" ren "%~dp0DefenderPerfAnalyzer-GUI.ps1.txt" "DefenderPerfAnalyzer-GUI.ps1"

if not exist "%~dp0DefenderPerfAnalyzer-GUI.ps1" (
    echo DefenderPerfAnalyzer-GUI.ps1 wurde in diesem Ordner nicht gefunden:
    echo %~dp0
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0DefenderPerfAnalyzer-GUI.ps1"
if errorlevel 1 (
    echo.
    echo Das Skript wurde mit einem Fehler beendet. Meldung siehe oben.
    pause
)
