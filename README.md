# Defender Performance Analyzer

PowerShell-GUI (WPF), die misst und vergleicht, wie viel Leistung Microsoft Defender auf Citrix-Workern (Multisession, non-persistent) braucht. Alle Messungen laufen per PowerShell Remoting parallel auf mehreren Servern.

## Funktionen

| Tab | Inhalt |
|---|---|
| **Server & Aufnahme** | Serverliste eingeben oder laden, Verbindung testen, Defender-Performance-Aufnahme (WPR) mit wählbarer Dauer starten, ETL-Dateien einsammeln und auswerten. Vorhandene ETL-Dateien lassen sich auch ohne neue Aufnahme auswerten. |
| **Ergebnisse** | Scanlast pro Worker, Vergleich der gescannten Pfade, Prozesse und Dateiendungen, Detailansicht mit Filter, automatische Hinweise (z.B. VHDX wird gescannt, FSLogix/Citrix in den Top 10) |
| **Ressourcen: Defender vs. Rest** | Misst CPU, RAM und I/O aller Prozesse und vergleicht Defender mit Citrix, FSLogix, Office, Browser, Windows und Sonstigen: Anteil, Kerne, Spitzen, Top-Prozesse, Verlauf |
| **Defender-Features** | Aktive Defender-Einstellungen pro Worker: Antivirus, Cloud, ASR-Regeln, Netzwerkschutz, Ausschlüsse, MDE-Onboarding, GPO/MDM-Herkunft, Firewall, Endpoint-DLP-Status. Als Übersicht, Matrix mit Abweichungen und Liste. |
| **DLP (Purview)** | DLP-Richtlinien und -Regeln aus dem Tenant (Modus, Geltungsbereich, Bedingungen, Endpoint-Aktionen) |
| **Einstellungen** | Alle Parameter, gespeichert unter `%APPDATA%\DefenderPerfGui\settings.json` |

Alle Tabellen sind sortierbar und lassen sich als CSV und Excel exportieren.

## Voraussetzungen

**Admin-PC**
- Windows PowerShell 5.1 oder PowerShell 7 (Windows)
- Für die lokale Auswertung: Defender-Plattform ab 4.18.2108.7 (`Get-MpPerformanceReport`). Sonst wird auf den Workern ausgewertet.
- Optional: Modul `ImportExcel` für den Excel-Export
- Optional: Modul `ExchangeOnlineManagement` und mindestens die Rolle «View-Only DLP Compliance Management» für den Tab «DLP (Purview)»

**Worker**
- WinRM bzw. PowerShell Remoting, das ausführende Konto ist lokaler Administrator
- Defender-Plattform ab 4.18.2108.7, `wpr.exe` (ab Windows Server 2016 vorhanden)

## Start

`DefenderPerfAnalyzer-GUI.ps1` und `Start-DefenderPerfAnalyzer.cmd` in denselben Ordner legen und `Start-DefenderPerfAnalyzer.cmd` per Doppelklick starten.

Alternativ:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\DefenderPerfAnalyzer-GUI.ps1
```

## Hinweise zur Messung

- Der Performance Analyzer (WPR-Aufnahme) erfasst nur Antivirus-Scans, nicht DLP-Klassifizierung oder EDR (MsSense).
- Die Ressourcenmessung liefert für Defender eine Untergrenze: Ein Teil der Scanarbeit des Filtertreibers wird dem aufrufenden Prozess angerechnet. Der Aufwand der Messung selbst ist herausgerechnet und wird separat ausgewiesen.
- Wird das Fenster während einer Aufnahme geschlossen, läuft die Aufnahme auf den Workern weiter. Stoppen mit `wpr -cancel -instancename DefenderPerfGui`.
- Ein Teil der Remote-Aufnahme stützt sich auf undokumentierte Details (Pfad des Defender-WPR-Profils, Format der Endpoint-DLP-Policy auf dem Gerät). Neue Versionen zuerst mit wenigen Workern testen.
