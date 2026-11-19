<#
.SYNOPSIS
    Defender Performance Analyzer mit GUI – Aufnahme und Vergleich der Defender-Scanlast auf Citrix-Workern.

.DESCRIPTION
    - Server eingeben (einer pro Zeile) oder aus Datei laden
    - Verbindung testen (WinRM, Defender-Plattform, WPR, Speicherplatz)
    - Zeitgesteuerte Aufnahme auf allen Servern parallel (WPR mit dem Defender-Profil von New-MpPerformanceRecording)
    - ETL-Dateien automatisch einsammeln und auswerten (lokal oder auf dem Worker)
    - Ergebnisse direkt in der GUI: Zusammenfassung, Vergleich Pfade/Prozesse/Endungen, Details mit Filter, automatische Hinweise
    - Vorhandene ETL-Dateien auswerten (ohne neue Aufnahme)
    - Export nach CSV und Excel (Excel benoetigt das Modul ImportExcel)
    - Defender-Features: aktive Einstellungen pro Worker (AV, Cloud, ASR-Regeln, Netzwerkschutz, Ausschluesse,
      MDE-Onboarding, GPO-/MDM-Herkunft, Firewall, Endpoint-DLP-Status auf dem Geraet) als Uebersicht, Matrix und Liste
    - Ressourcen: misst CPU, RAM und I/O aller Prozesse auf den Workern und vergleicht Defender mit dem Rest
      (Anteil an der genutzten CPU, Kerne, Spitzen, Kategorien Citrix/FSLogix/Office/Browser/Windows, Top-Prozesse, Verlauf)
    - DLP (Purview): alle DLP-Richtlinien und -Regeln aus dem Tenant (Modus, Scope, Bedingungen, Endpoint-Aktionen)
      ueber Security & Compliance PowerShell (Modul ExchangeOnlineManagement, Rolle mind. "View-Only DLP Compliance Management")
    - Alle Einstellungen in der GUI, gespeichert unter %APPDATA%\DefenderPerfGui\settings.json

.NOTES
    Voraussetzungen
      Admin-PC : Windows PowerShell 5.1 oder PowerShell 7 (Windows), fuer lokale Auswertung Defender-Plattform >= 4.18.2108.7
      Worker   : WinRM/PowerShell Remoting, lokale Adminrechte, Defender-Plattform >= 4.18.2108.7, wpr.exe (ab Server 2016 vorhanden)
    Das Tool misst nur Antivirus-Scans (Microsoft-Antimalware-Engine), nicht DLP-Klassifizierung oder EDR (MsSense).
#>

#region Start in STA sicherstellen (WPF)
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $exe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $exe -ArgumentList @('-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    return
}
#endregion

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

#region Sortierung fuer Tabellen mit PowerShell-Objekten (Zahlen numerisch, Text alphabetisch, leere Werte am Ende)
if (-not ('DefPerfGui.PSPropertyComparer' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Globalization;
using System.Management.Automation;

namespace DefPerfGui {
    public class PSPropertyComparer : IComparer {
        private readonly string _prop;
        private readonly int _dir;
        public PSPropertyComparer(string property, bool descending) {
            _prop = property;
            _dir = descending ? -1 : 1;
        }
        private object GetValue(object o) {
            if (o == null) return null;
            PSObject pso = o as PSObject;
            if (pso == null) pso = PSObject.AsPSObject(o);
            PSPropertyInfo p = pso.Properties[_prop];
            if (p == null) return null;
            object v;
            try { v = p.Value; } catch { return null; }
            PSObject inner = v as PSObject;
            if (inner != null) v = inner.BaseObject;
            return v;
        }
        private static bool IsEmpty(object v) {
            if (v == null) return true;
            string s = v as string;
            return s != null && (s.Trim().Length == 0 || s == "-" || s == "—");
        }
        private static bool TryNumber(object v, out double d) {
            d = 0;
            if (v is DateTime) { d = ((DateTime)v).Ticks; return true; }
            if (v is bool) return false;
            if (v is sbyte || v is byte || v is short || v is ushort || v is int || v is uint ||
                v is long || v is ulong || v is float || v is double || v is decimal) {
                d = Convert.ToDouble(v, CultureInfo.InvariantCulture);
                return true;
            }
            string s = v as string;
            if (s != null) {
                s = s.Trim();
                if (s.EndsWith("%")) s = s.Substring(0, s.Length - 1).Trim();
                return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out d);
            }
            return false;
        }
        public int Compare(object x, object y) {
            object vx = GetValue(x);
            object vy = GetValue(y);
            bool ex = IsEmpty(vx), ey = IsEmpty(vy);
            if (ex && ey) return 0;
            if (ex) return 1;     // leere Werte immer am Ende
            if (ey) return -1;
            double dx, dy;
            bool nx = TryNumber(vx, out dx), ny = TryNumber(vy, out dy);
            if (nx && ny) return _dir * dx.CompareTo(dy);
            if (nx) return _dir * -1;   // Zahlen vor Text
            if (ny) return _dir * 1;
            return _dir * string.Compare(vx.ToString(), vy.ToString(), StringComparison.CurrentCultureIgnoreCase);
        }
    }
}
'@
}
#endregion

#region Gemeinsamer Zustand (GUI <-> Hintergrund)
$sync = [hashtable]::Synchronized(@{
    Log          = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
    Servers      = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    ServersDirty = $false
    Busy         = $false
    Cancel       = $false
    StopNow      = $false
    Progress     = 0
    ProgressText = ''
    Results      = $null
    ResultsReady = $false
    LogFile      = $null
    FeatResults  = $null
    FeatReady    = $false
    DlpResults   = $null
    DlpReady     = $false
    ResResults   = $null
    ResReady     = $false
})
#endregion

#region Kernfunktionen (laufen in GUI und Hintergrund-Runspace)
$CoreBlock = {

    function Write-Log {
        param([string]$Message, [string]$Level = 'INFO')
        $sync.Log.Enqueue(('{0:HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message))
    }

    function Get-ShortName {
        param([string]$Name)
        if ($Name -match '^\d{1,3}(\.\d{1,3}){3}$') { return ($Name -replace '\.', '-') }
        return (($Name -split '\.')[0]).ToUpper()
    }

    function Set-ServerStatus {
        param([string]$Server, [hashtable]$Values)
        foreach ($o in $sync.Servers) {
            if ($o.Server -eq $Server -or $o.Worker -eq $Server) {
                foreach ($k in $Values.Keys) { $o.$k = $Values[$k] }
            }
        }
        $sync.ServersDirty = $true
    }

    function Get-Prop {
        param($Object, [string[]]$Names)
        if ($null -eq $Object) { return $null }
        foreach ($n in $Names) {
            $p = $Object.PSObject.Properties[$n]
            if ($p) { return $p.Value }
        }
        return $null
    }

    function ConvertTo-Ms {
        # Normalisiert eine Dauer (TimeSpan, Zahl, JSON-TimeSpan oder Text wie "12.3ms") auf Millisekunden
        param($Value)
        if ($null -eq $Value -or "$Value" -eq '') { return $null }
        if ($Value -is [TimeSpan]) { return [math]::Round($Value.TotalMilliseconds, 3) }
        if ($Value -is [ValueType] -and $Value -isnot [bool] -and $Value -isnot [datetime]) {
            $d = [double]$Value
            switch ($global:DefPerfDurationUnit) {
                'Milliseconds' { return [math]::Round($d, 3) }
                'Seconds'      { return [math]::Round($d * 1000, 3) }
                default        { return [math]::Round($d / 10000, 3) }   # Ticks (100 ns)
            }
        }
        if ($Value -is [psobject] -and $Value.PSObject.Properties['TotalMilliseconds']) {
            return [math]::Round([double]$Value.TotalMilliseconds, 3)
        }
        if ($Value -is [psobject] -and $Value.PSObject.Properties['Ticks']) {
            return [math]::Round([double]$Value.Ticks / 10000, 3)
        }
        $s = "$Value".Trim()
        $inv = [Globalization.CultureInfo]::InvariantCulture
        if ($s -match '^(?<n>[\d\.]+)\s*(?<u>ms|us|µs|ns|sec|s|min)$') {
            $n = [double]::Parse($Matches.n, $inv)
            switch ($Matches.u) {
                'ns'  { return [math]::Round($n / 1e6, 3) }
                'us'  { return [math]::Round($n / 1000, 3) }
                'µs'  { return [math]::Round($n / 1000, 3) }
                'ms'  { return [math]::Round($n, 3) }
                'sec' { return [math]::Round($n * 1000, 3) }
                's'   { return [math]::Round($n * 1000, 3) }
                'min' { return [math]::Round($n * 60000, 3) }
            }
        }
        if ($s -match ':') {
            $ts = [TimeSpan]::Zero
            if ([TimeSpan]::TryParse($s, $inv, [ref]$ts)) { return [math]::Round($ts.TotalMilliseconds, 3) }
        }
        $num = 0.0
        if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, $inv, [ref]$num)) { return (ConvertTo-Ms -Value $num) }
        return $null
    }

    function ConvertTo-DateTimeSafe {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [datetime]) { return $Value }
        $s = "$Value"
        if ($s -match '/Date\((?<ms>-?\d+)') {
            return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$Matches.ms).LocalDateTime
        }
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$dt)) { return $dt }
        return $null
    }

    $global:DefPerfKeyNames = @{
        TopPaths      = @('Path', 'Directory', 'Folder')
        TopFiles      = @('Path', 'File', 'FilePath')
        TopProcesses  = @('ProcessPath', 'Process', 'ProcessName', 'Image', 'Path')
        TopExtensions = @('Extension', 'Ext')
    }
    $global:DefPerfTotalNames = @('TotalDuration', 'Duration', 'Total')

    function Expand-ReportSection {
        param($Items, [string]$Section, [string]$Worker, [int]$Level = 1, [string]$Parent = '')
        $keyNames = $global:DefPerfKeyNames[$Section]
        foreach ($item in @($Items)) {
            if ($null -eq $item) { continue }
            $key = Get-Prop $item $keyNames
            if ($null -eq $key) { continue }
            [pscustomobject]@{
                Worker            = $Worker
                Level             = $Level
                Key               = "$key"
                Parent            = $Parent
                Count             = Get-Prop $item @('Count', 'ScanCount', 'Scans')
                TotalDuration_ms  = ConvertTo-Ms (Get-Prop $item $global:DefPerfTotalNames)
                AvgDuration_ms    = ConvertTo-Ms (Get-Prop $item @('AverageDuration', 'AvgDuration', 'Average'))
                MaxDuration_ms    = ConvertTo-Ms (Get-Prop $item @('MaxDuration', 'Max'))
                MedianDuration_ms = ConvertTo-Ms (Get-Prop $item @('MedianDuration', 'Median'))
            }
            foreach ($p in $item.PSObject.Properties) {
                $v = $p.Value
                if ($v -is [string] -or $v -isnot [System.Collections.IEnumerable]) { continue }
                $children = @($v)
                if ($children.Count -gt 0 -and $children[0] -isnot [ValueType] -and $children[0] -isnot [string] -and
                    $null -ne (Get-Prop $children[0] $keyNames) -and
                    $null -ne (Get-Prop $children[0] $global:DefPerfTotalNames)) {
                    Expand-ReportSection -Items $children -Section $Section -Worker $Worker -Level ($Level + 1) -Parent "$key"
                }
            }
        }
    }

    function Get-ColumnName {
        param([string]$Worker)
        return (($Worker -replace '[^\w\-]', '_') + '_ms')
    }

    function New-CompareTable {
        param([object[]]$Rows, [string[]]$Workers, [int]$Take)
        if (-not $Rows) { return @() }
        $table = foreach ($g in ($Rows | Group-Object Key)) {
            $o = [ordered]@{ Key = $g.Name }
            $sum = 0.0; $present = 0
            foreach ($w in $Workers) {
                $val = ($g.Group | Where-Object Worker -eq $w | Measure-Object TotalDuration_ms -Sum).Sum
                if ($null -ne $val -and $val -gt 0) { $present++ } else { $val = 0 }
                $o[(Get-ColumnName $w)] = [math]::Round([double]$val, 1)
                $sum += $val
            }
            $o['Summe_ms'] = [math]::Round($sum, 1)
            $o['Mittel_ms'] = [math]::Round($sum / [math]::Max($Workers.Count, 1), 1)
            $o['Anzahl_Worker'] = $present
            [pscustomobject]$o
        }
        @($table | Sort-Object Summe_ms -Descending | Select-Object -First $Take)
    }

    function Get-ReportParams {
        param($Settings)
        @{
            TopPaths      = [int]$Settings.Top
            TopPathsDepth = [int]$Settings.TopPathsDepth
            TopProcesses  = [int]$Settings.Top
            TopFiles      = [int]$Settings.Top
            TopExtensions = 1000
            TopScans      = [int]$Settings.TopScans
        }
    }

    function Get-UniqueLabel {
        param([string]$Label, $Used)
        $l = $Label; $n = 2
        while ($Used.Contains($l)) { $l = "$Label-$n"; $n++ }
        [void]$Used.Add($l)
        return $l
    }

    function Build-Results {
        # $Items: Objekte mit Worker, File, SizeMB, Report, Error
        param($Items, $Settings, [string]$OutputFolder)
        $global:DefPerfDurationUnit = $Settings.DurationUnit

        $allPaths = New-Object System.Collections.Generic.List[object]
        $allProcs = New-Object System.Collections.Generic.List[object]
        $allExts  = New-Object System.Collections.Generic.List[object]
        $allFiles = New-Object System.Collections.Generic.List[object]
        $allScans = New-Object System.Collections.Generic.List[object]
        $summary  = New-Object System.Collections.Generic.List[object]

        foreach ($it in $Items) {
            if ($it.Error -or $null -eq $it.Report) {
                $summary.Add([pscustomobject][ordered]@{
                    Worker = $it.Worker; Datei = $it.File; Groesse_MB = $it.SizeMB; Zeitraum_Min = $null; Scans_Total = $null
                    Scanzeit_Total_s = $null; Scans_pro_Min = $null; Scanzeit_s_pro_Min = $null; TopScans_ausgewertet = $null
                    NotSkipped = $null; UserSkipped = $null; Optimization = $null; Top_Pfad = $null; Top_Pfad_s = $null
                    Top_Prozess = $null; Top_Prozess_s = $null; Anteil_Prozent = 0; Fehler = "$($it.Error)"
                })
                continue
            }
            $report = $it.Report
            if ($report -is [string]) { $report = $report | ConvertFrom-Json }
            $label = $it.Worker

            $paths = @(Expand-ReportSection -Items (Get-Prop $report 'TopPaths')      -Section TopPaths      -Worker $label)
            $procs = @(Expand-ReportSection -Items (Get-Prop $report 'TopProcesses')  -Section TopProcesses  -Worker $label)
            $exts  = @(Expand-ReportSection -Items (Get-Prop $report 'TopExtensions') -Section TopExtensions -Worker $label)
            $files = @(Expand-ReportSection -Items (Get-Prop $report 'TopFiles')      -Section TopFiles      -Worker $label)
            foreach ($x in $paths) { $allPaths.Add($x) }
            foreach ($x in $procs) { $allProcs.Add($x) }
            foreach ($x in $exts)  { $allExts.Add($x) }
            foreach ($x in $files) { $allFiles.Add($x) }

            $scans = @(foreach ($s in @(Get-Prop $report 'TopScans')) {
                if ($null -eq $s) { continue }
                [pscustomobject]@{
                    Worker      = $label
                    Path        = Get-Prop $s @('Path', 'File', 'FilePath')
                    Process     = Get-Prop $s @('ProcessPath', 'Process', 'ProcessName', 'Image')
                    ScanType    = Get-Prop $s @('ScanType', 'Type')
                    Reason      = Get-Prop $s @('Reason', 'ScanReason')
                    SkipReason  = Get-Prop $s @('SkipReason')
                    Duration_ms = ConvertTo-Ms (Get-Prop $s @('Duration', 'TotalDuration'))
                    StartTime   = ConvertTo-DateTimeSafe (Get-Prop $s @('StartTime', 'Start'))
                    EndTime     = ConvertTo-DateTimeSafe (Get-Prop $s @('EndTime', 'End'))
                }
            })
            foreach ($x in $scans) { $allScans.Add($x) }

            $topLevelExts = @($exts | Where-Object Level -eq 1)
            $totalMs   = ($topLevelExts | Measure-Object TotalDuration_ms -Sum).Sum
            $scanCount = ($topLevelExts | Measure-Object Count -Sum).Sum
            $starts = @($scans | Where-Object StartTime | ForEach-Object StartTime)
            $ends   = @($scans | Where-Object EndTime   | ForEach-Object EndTime)
            $minutes = $null
            if ($starts.Count -and $ends.Count) {
                $span = (($ends | Measure-Object -Maximum).Maximum - ($starts | Measure-Object -Minimum).Minimum).TotalMinutes
                if ($span -gt 0) { $minutes = [math]::Round($span, 1) }
            }
            if ($it.RecordMinutes) { $minutes = [double]$it.RecordMinutes }   # bei eigener Aufnahme ist die Dauer bekannt

            $skip = @($scans | Group-Object { if ($_.SkipReason) { "$($_.SkipReason)" } else { 'n/a' } })
            $topPath = $paths | Where-Object Level -eq 1 | Sort-Object TotalDuration_ms -Descending | Select-Object -First 1
            $topProc = $procs | Sort-Object TotalDuration_ms -Descending | Select-Object -First 1

            $summary.Add([pscustomobject][ordered]@{
                Worker               = $label
                Datei                = $it.File
                Groesse_MB           = $it.SizeMB
                Zeitraum_Min         = $minutes
                Scans_Total          = $scanCount
                Scanzeit_Total_s     = $(if ($totalMs) { [math]::Round($totalMs / 1000, 2) } else { $null })
                Scans_pro_Min        = $(if ($minutes -and $scanCount) { [math]::Round($scanCount / $minutes, 1) } else { $null })
                Scanzeit_s_pro_Min   = $(if ($minutes -and $totalMs) { [math]::Round($totalMs / 1000 / $minutes, 2) } else { $null })
                TopScans_ausgewertet = $scans.Count
                NotSkipped           = ($skip | Where-Object Name -match '^Not\s*Skipped' | Measure-Object Count -Sum).Sum
                UserSkipped          = ($skip | Where-Object Name -match 'User'           | Measure-Object Count -Sum).Sum
                Optimization         = ($skip | Where-Object Name -match 'Optimi'         | Measure-Object Count -Sum).Sum
                Top_Pfad             = $topPath.Key
                Top_Pfad_s           = $(if ($topPath) { [math]::Round($topPath.TotalDuration_ms / 1000, 2) } else { $null })
                Top_Prozess          = $topProc.Key
                Top_Prozess_s        = $(if ($topProc) { [math]::Round($topProc.TotalDuration_ms / 1000, 2) } else { $null })
                Anteil_Prozent       = 0
                Fehler               = $null
            })
        }

        $okRows  = @($summary | Where-Object { -not $_.Fehler })
        $workers = @($okRows | ForEach-Object Worker)

        # Relative Scanlast fuer den Balken (pro Minute, sonst total)
        $metricName = 'Scanzeit_s_pro_Min'
        if (@($okRows | Where-Object { $null -eq $_.Scanzeit_s_pro_Min }).Count -gt 0) { $metricName = 'Scanzeit_Total_s' }
        $max = ($okRows | Measure-Object $metricName -Maximum).Maximum
        if ($max -gt 0) { foreach ($r in $okRows) { $r.Anteil_Prozent = [math]::Round([double]$r.$metricName / $max * 100, 0) } }

        # Pfade: nur Blatt-Eintraege vergleichen (keine Doppelzaehlung von Ober-/Unterpfaden)
        $parentSet = @{}
        foreach ($r in $allPaths) { if ($r.Parent) { $parentSet["$($r.Worker)|$($r.Parent)"] = $true } }
        $leafPaths = @($allPaths | Where-Object { -not $parentSet.ContainsKey("$($_.Worker)|$($_.Key)") })

        $res = @{
            Summary      = $summary.ToArray()
            CmpPaths     = New-CompareTable -Rows $leafPaths -Workers $workers -Take ([int]$Settings.CompareTop)
            CmpProcs     = New-CompareTable -Rows $allProcs.ToArray() -Workers $workers -Take ([int]$Settings.CompareTop)
            CmpExts      = New-CompareTable -Rows @($allExts | Where-Object Level -eq 1) -Workers $workers -Take ([int]$Settings.CompareTop)
            AllPaths     = $allPaths.ToArray()
            AllProcs     = $allProcs.ToArray()
            AllExts      = $allExts.ToArray()
            AllFiles     = $allFiles.ToArray()
            AllScans     = $allScans.ToArray()
            Workers      = $workers
            MetricName   = $metricName
            OutputFolder = $OutputFolder
            Created      = Get-Date
        }
        $res.Hints = Get-Hints -Results $res
        return $res
    }

    function Get-Hints {
        param($Results)
        $h = New-Object System.Collections.Generic.List[string]

        foreach ($s in @($Results.Summary | Where-Object Fehler)) {
            $h.Add("✖ $($s.Worker): Auswertung fehlgeschlagen – $($s.Fehler)")
        }

        $vhdScans = @($Results.AllScans | Where-Object { "$($_.Path)" -match '\.vhdx?$' -and "$($_.SkipReason)" -notmatch 'User' })
        if ($vhdScans.Count) {
            $ms = [math]::Round(($vhdScans | Measure-Object Duration_ms -Sum).Sum, 0)
            $h.Add("⚠ VHD/VHDX-Dateien werden gescannt ($($vhdScans.Count) Scans, $ms ms). FSLogix-Exclusions (*.vhd, *.vhdx, Container-Pfade) pruefen.")
        }
        elseif (@($Results.AllFiles | Where-Object { $_.Key -match '\.vhdx?$' }).Count) {
            $h.Add('⚠ VHD/VHDX-Dateien erscheinen in den Top-Dateien. FSLogix-Exclusions pruefen.')
        }

        $top10 = @($Results.CmpPaths | Select-Object -First 10) + @($Results.CmpProcs | Select-Object -First 10)
        $fsl = @($top10 | Where-Object { $_.Key -match 'FSLogix|frxsvc|frxccds|\\frx' } | ForEach-Object Key | Select-Object -Unique)
        if ($fsl.Count) { $h.Add("⚠ FSLogix unter den Top 10: $($fsl -join ', '). Microsoft-Empfehlungen fuer FSLogix-Exclusions pruefen.") }

        $ctx = @($top10 | Where-Object { $_.Key -match 'Citrix' } | ForEach-Object Key | Select-Object -Unique)
        if ($ctx.Count) { $h.Add("ℹ Citrix-Komponenten unter den Top 10: $($ctx -join ', '). Exclusions gemaess Citrix-Empfehlung pruefen.") }

        $ok = @($Results.Summary | Where-Object { -not $_.Fehler -and $null -ne $_.($Results.MetricName) })
        if ($ok.Count -ge 3) {
            $vals = @($ok | ForEach-Object { [double]$_.($Results.MetricName) } | Sort-Object)
            $mid = [int][math]::Floor($vals.Count / 2)
            $median = if ($vals.Count % 2) { $vals[$mid] } else { ($vals[$mid - 1] + $vals[$mid]) / 2 }
            if ($median -gt 0) {
                foreach ($r in $ok) {
                    if ([double]$r.($Results.MetricName) -gt 2 * $median) {
                        $h.Add(("⚠ Ausreisser: {0} hat {1} {2} (Median {3:N2}). Diesen Worker genauer anschauen." -f $r.Worker, $r.($Results.MetricName), $Results.MetricName, $median))
                    }
                }
            }
        }

        $extAgg = @($Results.AllExts | Where-Object Level -eq 1 | Group-Object Key | ForEach-Object {
            [pscustomobject]@{ Key = $_.Name; Ms = ($_.Group | Measure-Object TotalDuration_ms -Sum).Sum }
        } | Sort-Object Ms -Descending)
        $extTotal = ($extAgg | Measure-Object Ms -Sum).Sum
        if ($extAgg.Count -and $extTotal -gt 0) {
            $share = [math]::Round($extAgg[0].Ms / $extTotal * 100, 0)
            if ($share -ge 30) { $h.Add("ℹ Dateiendung '$($extAgg[0].Key)' verursacht $share % der gesamten Scanzeit.") }
        }

        $userSkipped = ($Results.Summary | Measure-Object UserSkipped -Sum).Sum
        $evaluated   = ($Results.Summary | Measure-Object TopScans_ausgewertet -Sum).Sum
        if ($evaluated) { $h.Add("ℹ $([int]$userSkipped) von $([int]$evaluated) ausgewerteten Einzelscans wurden durch Exclusions uebersprungen (User skipped).") }

        if (-not ($h | Where-Object { $_ -match '^(⚠|✖)' })) { $h.Insert(0, '✔ Keine Auffaelligkeiten nach den eingebauten Regeln.') }
        $h.Add('')
        $h.Add('Hinweis: Gemessen werden nur Antivirus-Scans, nicht DLP-Klassifizierung oder EDR (MsSense).')
        return ($h -join [Environment]::NewLine)
    }

    function Export-Results {
        param($Results, [string]$Folder, $Settings)
        $null = New-Item -ItemType Directory -Path $Folder -Force
        $sets = [ordered]@{
            'Summary'               = $Results.Summary
            'Compare_TopPaths'      = $Results.CmpPaths
            'Compare_TopProcesses'  = $Results.CmpProcs
            'Compare_TopExtensions' = $Results.CmpExts
            'All_TopPaths'          = $Results.AllPaths
            'All_TopProcesses'      = $Results.AllProcs
            'All_TopExtensions'     = $Results.AllExts
            'All_TopFiles'          = $Results.AllFiles
            'All_TopScans'          = $Results.AllScans
        }
        $written = New-Object System.Collections.Generic.List[string]
        Set-Content -Path (Join-Path $Folder 'Hinweise.txt') -Value $Results.Hints -Encoding UTF8
        if ($Settings.ExportCsv) {
            foreach ($name in $sets.Keys) {
                $data = @($sets[$name])
                if ($data.Count -eq 0) { continue }
                $file = Join-Path $Folder "$name.csv"
                $data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -Delimiter ([char]$Settings.CsvDelimiter)
                $written.Add($file)
            }
        }
        if ($Settings.ExportExcel) {
            if (Get-Module -ListAvailable -Name ImportExcel) {
                Import-Module ImportExcel -ErrorAction Stop
                $xlsx = Join-Path $Folder 'Defender_Performance_Vergleich.xlsx'
                if (Test-Path $xlsx) { Remove-Item $xlsx -Force }
                foreach ($name in $sets.Keys) {
                    $data = @($sets[$name])
                    if ($data.Count -eq 0) { continue }
                    $data | Export-Excel -Path $xlsx -WorksheetName $name -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium2 -TableName ($name -replace '\W', '')
                }
                $written.Add($xlsx)
            }
            else {
                Write-Log 'Excel-Export uebersprungen: Modul ImportExcel fehlt (Install-Module ImportExcel -Scope CurrentUser).' 'WARN'
            }
        }
        return $written
    }

    #----- Remote-Funktionen (werden per Invoke-Command auf den Workern ausgefuehrt) -----

    function Find-MpWprp {
        # Sucht das WPR-Profil, das New-MpPerformanceRecording verwendet
        $cands = New-Object System.Collections.Generic.List[object]
        $cmd = Get-Command New-MpPerformanceRecording -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Module -and $cmd.Module.ModuleBase) {
            Get-ChildItem -Path $cmd.Module.ModuleBase -Filter *.wprp -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $cands.Add($_) }
        }
        Get-ChildItem -Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules" -Filter *.wprp -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'Defender' } | ForEach-Object { $cands.Add($_) }
        $plat = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
        if (Test-Path $plat) {
            $latest = Get-ChildItem $plat -Directory -ErrorAction SilentlyContinue |
                Sort-Object { try { [version]($_.Name -replace '-.*$', '') } catch { [version]'0.0' } } -Descending | Select-Object -First 1
            if ($latest) { Get-ChildItem $latest.FullName -Filter *.wprp -ErrorAction SilentlyContinue | ForEach-Object { $cands.Add($_) } }
        }
        $f = $cands | Sort-Object { if ($_.Name -match 'MpPerformance') { 0 } elseif ($_.Name -match 'Defender|Antimalware|Mp') { 1 } else { 2 } } | Select-Object -First 1
        if (-not $f) { return $null }
        [xml]$x = Get-Content -LiteralPath $f.FullName -Raw
        $profiles = @($x.SelectNodes("//*[local-name()='Profile']"))
        $p = $profiles | Where-Object { $_.GetAttribute('LoggingMode') -eq 'File' } | Select-Object -First 1
        if (-not $p) { $p = $profiles | Select-Object -First 1 }
        if (-not $p) { return $null }
        $name = $p.GetAttribute('Name'); $level = $p.GetAttribute('DetailLevel')
        $sel = if ($level) { "$name.$level" } else { $name }
        [pscustomobject]@{
            Arg      = "$($f.FullName)!$sel"
            FileMode = ($p.GetAttribute('LoggingMode') -eq 'File')
            Name     = "$($f.Name)!$sel"
        }
    }

    function Get-FallbackWprpXml {
        @'
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="DefenderPerfGui">
  <Profiles>
    <SystemCollector Id="SC_DefPerf" Name="NT Kernel Logger">
      <BufferSize Value="1024"/>
      <Buffers Value="64"/>
    </SystemCollector>
    <EventCollector Id="EC_DefPerf" Name="DefenderPerfGui Event Collector">
      <BufferSize Value="1024"/>
      <Buffers Value="64"/>
    </EventCollector>
    <SystemProvider Id="SP_DefPerf">
      <Keywords>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="Loader"/>
      </Keywords>
    </SystemProvider>
    <EventProvider Id="EP_Antimalware" Name="Microsoft-Antimalware-Engine" Level="5"/>
    <Profile Id="DefPerfGui.Verbose.File" Name="DefPerfGui" Description="Defender AV Scan-Performance" LoggingMode="File" DetailLevel="Verbose">
      <Collectors>
        <SystemCollectorId Value="SC_DefPerf">
          <SystemProviderId Value="SP_DefPerf"/>
        </SystemCollectorId>
        <EventCollectorId Value="EC_DefPerf">
          <EventProviders>
            <EventProviderId Value="EP_Antimalware"/>
          </EventProviders>
        </EventCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
'@
    }

    function Get-HelperText {
        "function Find-MpWprp {`n$(${function:Find-MpWprp})`n}"
    }

    function Remote-Check {
        param($RemoteDir, $HelperText)
        . ([scriptblock]::Create($HelperText))
        $m = New-Object System.Collections.Generic.List[string]; $ok = $true
        $plat = $null; $rtp = $null
        try { $st = Get-MpComputerStatus -ErrorAction Stop; $plat = $st.AMProductVersion; $rtp = $st.RealTimeProtectionEnabled }
        catch { $ok = $false; $m.Add('Defender-Status nicht lesbar') }
        if ($plat) { try { if ([version]$plat -lt [version]'4.18.2108.7') { $ok = $false; $m.Add('Plattform aelter als 4.18.2108.7') } } catch {} }
        if ($rtp -eq $false) { $m.Add('Echtzeitschutz ist aus') }
        if (-not (Get-Command wpr.exe -ErrorAction SilentlyContinue)) { $ok = $false; $m.Add('wpr.exe nicht gefunden') }
        $prof = $null; try { $prof = Find-MpWprp } catch {}
        if (-not $prof) { $m.Add('Defender-WPR-Profil nicht gefunden (Fallback moeglich)') }
        $free = $null
        try {
            $root = [IO.Path]::GetPathRoot($RemoteDir)
            $d = Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction Stop
            $free = [math]::Round($d.Free / 1GB, 1)
            if ($free -lt 2) { $m.Add("Wenig Platz auf $root ($free GB)") }
        } catch {}
        $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        [pscustomobject]@{
            Ok        = $ok
            Plattform = $plat
            Profil    = $(if ($prof) { $prof.Name } else { '-' })
            Info      = ('{0}; {1} GB frei' -f $os, $free)
            Meldung   = ($m -join '; ')
        }
    }

    function Remote-Start {
        param($RemoteDir, $Instance, $CancelExisting, $AllowFallback, $FallbackXml, $HelperText)
        . ([scriptblock]::Create($HelperText))
        $null = New-Item -ItemType Directory -Path $RemoteDir -Force
        $prof = $null; try { $prof = Find-MpWprp } catch {}
        if (-not $prof -and $AllowFallback) {
            $wprp = Join-Path $RemoteDir 'DefenderPerfGui.wprp'
            Set-Content -Path $wprp -Value $FallbackXml -Encoding UTF8
            $prof = [pscustomobject]@{ Arg = "$wprp!DefPerfGui.Verbose"; FileMode = $true; Name = 'Fallback-Profil (eigenes)' }
        }
        if (-not $prof) { return [pscustomobject]@{ Ok = $false; Profil = '-'; Meldung = 'Kein WPR-Profil gefunden' } }
        if ($CancelExisting) {
            & wpr.exe -cancel -instancename $Instance 2>&1 | Out-Null
            & wpr.exe -cancel -instancename 'MSFT_MpPerformanceRecording' 2>&1 | Out-Null
        }
        $wprArgs = @('-start', $prof.Arg)
        if ($prof.FileMode) { $wprArgs += '-filemode' }
        $wprArgs += @('-instancename', $Instance)
        $out = & wpr.exe @wprArgs 2>&1 | Out-String
        $code = $LASTEXITCODE
        [pscustomobject]@{
            Ok      = ($code -eq 0)
            Profil  = $prof.Name
            Meldung = $(if ($code -eq 0) { 'Aufnahme laeuft' } else { ("wpr Exitcode {0}: {1}" -f $code, $out.Trim()) })
        }
    }

    function Remote-Stop {
        param($RemoteDir, $Instance, $Stamp)
        $name = '{0}_{1}.etl' -f $env:COMPUTERNAME, $Stamp
        $etl = Join-Path $RemoteDir $name
        $out = & wpr.exe -stop $etl -instancename $Instance 2>&1 | Out-String
        $code = $LASTEXITCODE
        $exists = Test-Path -LiteralPath $etl
        [pscustomobject]@{
            Ok      = ($code -eq 0 -and $exists)
            Path    = $etl
            Name    = $name
            SizeMB  = $(if ($exists) { [math]::Round((Get-Item -LiteralPath $etl).Length / 1MB, 1) } else { $null })
            Meldung = $(if ($code -eq 0) { 'Aufnahme gespeichert' } else { ("wpr Exitcode {0}: {1}" -f $code, $out.Trim()) })
        }
    }

    function Remote-Cancel {
        param($Instance)
        & wpr.exe -cancel -instancename $Instance 2>&1 | Out-Null
        $true
    }

    function Remote-Analyze {
        param($EtlPath, $ReportParams)
        Get-MpPerformanceReport -Path $EtlPath -Raw @ReportParams | ConvertTo-Json -Depth 12 -Compress
    }

    function Remote-Delete {
        param($Path)
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        $wprp = Join-Path (Split-Path $Path) 'DefenderPerfGui.wprp'
        if (Test-Path $wprp) { Remove-Item -LiteralPath $wprp -Force -ErrorAction SilentlyContinue }
    }

    #----- Verbindungen -----

    function Open-Sessions {
        param([string[]]$Servers, $Settings, $Credential)
        $p = @{ ComputerName = $Servers; ThrottleLimit = [int]$Settings.ThrottleLimit; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'sessErr' }
        if ($Credential) { $p.Credential = $Credential }
        $sess = @(New-PSSession @p)
        foreach ($s in $Servers) {
            if (-not ($sess | Where-Object { $_.ComputerName -eq $s })) {
                $msg = ($sessErr | Where-Object { $_.Exception.Message -match [regex]::Escape($s) } | Select-Object -First 1).Exception.Message
                if (-not $msg) { $msg = 'Verbindung fehlgeschlagen (WinRM, DNS, Firewall oder Berechtigung pruefen)' }
                $msg = ($msg -split "`n")[0].Trim()
                Set-ServerStatus $s @{ Status = 'Keine Verbindung'; Meldung = $msg }
                Write-Log "$s : $msg" 'ERROR'
            }
        }
        return $sess
    }

    function Repair-Sessions {
        param($Sessions, $Settings, $Credential)
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($s in $Sessions) {
            if ($s.State -eq 'Opened') { $out.Add($s); continue }
            Remove-PSSession $s -ErrorAction SilentlyContinue
            $p = @{ ComputerName = $s.ComputerName; ErrorAction = 'SilentlyContinue' }
            if ($Credential) { $p.Credential = $Credential }
            $n = New-PSSession @p
            if ($n) { $out.Add($n); Write-Log "$($s.ComputerName): Sitzung neu aufgebaut" }
            else { Set-ServerStatus $s.ComputerName @{ Status = 'Verbindung verloren' } }
        }
        return $out.ToArray()
    }

    function Invoke-OnSessions {
        param($Sessions, [scriptblock]$Block, [object[]]$ArgList, $Settings)
        if (-not $Sessions) { return @() }
        $res = @(Invoke-Command -Session $Sessions -ScriptBlock $Block -ArgumentList $ArgList -ThrottleLimit ([int]$Settings.ThrottleLimit) -ErrorAction SilentlyContinue -ErrorVariable invErr)
        foreach ($e in @($invErr)) {
            $cn = $e.OriginInfo.PSComputerName
            if (-not $cn) { $cn = "$($e.TargetObject)" }
            $msg = ($e.Exception.Message -split "`n")[0].Trim()
            if ($cn) { Set-ServerStatus $cn @{ Status = 'Fehler'; Meldung = $msg } }
            Write-Log "$cn : $msg" 'ERROR'
        }
        return $res
    }

    #----- Ablaeufe -----

    function Invoke-ConnectionTest {
        param($A)
        $S = $A.Settings
        Write-Log "Verbindungstest fuer $($A.Servers.Count) Server gestartet"
        foreach ($srv in $A.Servers) { Set-ServerStatus $srv @{ Status = 'Verbinde...' } }
        $sessions = Open-Sessions -Servers $A.Servers -Settings $S -Credential $A.Credential
        try {
            $res = Invoke-OnSessions -Sessions $sessions -Block ${function:Remote-Check} -ArgList @($S.RemoteFolder, (Get-HelperText)) -Settings $S
            foreach ($r in $res) {
                $status = if ($r.Ok) { 'Bereit' } else { 'Pruefen' }
                $msg = (@($r.Info, $r.Meldung) | Where-Object { $_ }) -join ' | '
                Set-ServerStatus $r.PSComputerName @{ Status = $status; Plattform = $r.Plattform; Profil = $r.Profil; Meldung = $msg }
                Write-Log ("{0}: {1} – {2}" -f $r.PSComputerName, $status, $msg)
            }
        }
        finally { if ($sessions) { Remove-PSSession $sessions -ErrorAction SilentlyContinue } }
        $ready = @($sync.Servers | Where-Object Status -eq 'Bereit').Count
        Write-Log "Verbindungstest abgeschlossen: $ready von $($A.Servers.Count) bereit"
    }

    function Get-ReportLocal {
        param([string]$Path, $Settings)
        $prm = Get-ReportParams $Settings
        $r = Get-MpPerformanceReport -Path $Path -Raw @prm
        if ($r -is [string]) { $r = $r | ConvertFrom-Json }
        return $r
    }

    function Complete-Analysis {
        param($Items, $Settings, [string]$OutputFolder)
        Write-Log 'Erstelle Vergleich und Hinweise...'
        $res = Build-Results -Items $Items -Settings $Settings -OutputFolder $OutputFolder
        if ($Settings.ExportCsv -or $Settings.ExportExcel) {
            try {
                $files = Export-Results -Results $res -Folder $OutputFolder -Settings $Settings
                Write-Log "Export: $($files.Count) Datei(en) in $OutputFolder"
            }
            catch { Write-Log "Export fehlgeschlagen: $($_.Exception.Message)" 'ERROR' }
        }
        $sync.Results = $res
        $sync.ResultsReady = $true
        Write-Log "Auswertung abgeschlossen ($(@($res.Workers).Count) Worker)."
    }

    function Invoke-RecordingWorkflow {
        param($A)
        $S = $A.Settings
        $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
        $runFolder = Join-Path $S.CollectFolder $stamp
        $null = New-Item -ItemType Directory -Path $runFolder -Force
        $sync.LogFile = Join-Path $runFolder 'Protokoll.txt'
        $minutes = [double]$S.RecordMinutes
        Write-Log "Aufnahme: $($A.Servers.Count) Server, $minutes Minuten, Ablage $runFolder"

        foreach ($srv in $A.Servers) { Set-ServerStatus $srv @{ Status = 'Verbinde...'; ETL_MB = $null; Meldung = '' } }
        $sessions = @(Open-Sessions -Servers $A.Servers -Settings $S -Credential $A.Credential)
        if (-not $sessions) { Write-Log 'Keine Verbindung zu einem Server moeglich. Abbruch.' 'ERROR'; return }

        try {
            # 1) Start
            $sync.ProgressText = 'Starte Aufnahmen...'
            $startRes = Invoke-OnSessions -Sessions $sessions -Block ${function:Remote-Start} -Settings $S -ArgList @(
                $S.RemoteFolder, $S.Instance, [bool]$S.CancelExisting, [bool]$S.FallbackProfile, (Get-FallbackWprpXml), (Get-HelperText))
            $active = New-Object System.Collections.Generic.List[string]
            foreach ($r in $startRes) {
                if ($r.Ok) { $active.Add($r.PSComputerName); Set-ServerStatus $r.PSComputerName @{ Status = 'Aufnahme laeuft'; Profil = $r.Profil; Meldung = $r.Meldung } }
                else { Set-ServerStatus $r.PSComputerName @{ Status = 'Start fehlgeschlagen'; Profil = $r.Profil; Meldung = $r.Meldung }; Write-Log "$($r.PSComputerName): $($r.Meldung)" 'ERROR' }
            }
            if ($active.Count -eq 0) { Write-Log 'Auf keinem Server konnte die Aufnahme gestartet werden.' 'ERROR'; return }
            $recSessions = @($sessions | Where-Object { $active -contains $_.ComputerName })
            Write-Log "Aufnahme laeuft auf $($active.Count) Server(n)."

            # 2) Warten
            $start = Get-Date
            $end = $start.AddMinutes($minutes)
            while ((Get-Date) -lt $end) {
                if ($sync.Cancel -or $sync.StopNow) { break }
                $left = $end - (Get-Date)
                $sync.Progress = [math]::Min(100, [math]::Round(((Get-Date) - $start).TotalSeconds / ($minutes * 60) * 100, 0))
                $sync.ProgressText = ('Aufnahme laeuft – noch {0:mm\:ss}' -f $left)
                Start-Sleep -Milliseconds 500
            }
            $actualMinutes = [math]::Round(((Get-Date) - $start).TotalMinutes, 1)

            # 3) Abbruch?
            $recSessions = Repair-Sessions -Sessions $recSessions -Settings $S -Credential $A.Credential
            if ($sync.Cancel) {
                $sync.ProgressText = 'Breche Aufnahmen ab...'
                $null = Invoke-OnSessions -Sessions $recSessions -Block ${function:Remote-Cancel} -ArgList @($S.Instance) -Settings $S
                foreach ($c in $active) { Set-ServerStatus $c @{ Status = 'Abgebrochen' } }
                Write-Log 'Aufnahme abgebrochen, keine Auswertung.' 'WARN'
                return
            }
            if ($sync.StopNow) { Write-Log "Aufnahme vorzeitig beendet nach $actualMinutes Minuten." }

            # 4) Stoppen
            $sync.Progress = 0
            $sync.ProgressText = 'Speichere Aufnahmen (wpr -stop)...'
            foreach ($c in $active) { Set-ServerStatus $c @{ Status = 'Speichere...' } }
            $stopRes = Invoke-OnSessions -Sessions $recSessions -Block ${function:Remote-Stop} -ArgList @($S.RemoteFolder, $S.Instance, $stamp) -Settings $S

            # 5) Einsammeln und auswerten
            $items = New-Object System.Collections.Generic.List[object]
            $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $prm = Get-ReportParams $S
            $i = 0; $n = @($stopRes).Count
            $localAvailable = [bool](Get-Command Get-MpPerformanceReport -ErrorAction SilentlyContinue)
            foreach ($r in $stopRes) {
                $i++
                $cn = $r.PSComputerName
                $label = Get-UniqueLabel -Label (Get-ShortName $cn) -Used $used
                $sync.Progress = [math]::Round(($i - 1) / [math]::Max($n, 1) * 100, 0)
                $sync.ProgressText = "Werte aus: $label ($i/$n)"
                if ($sync.Cancel) { Write-Log 'Abbruch waehrend der Auswertung.' 'WARN'; break }
                if (-not $r.Ok) {
                    Set-ServerStatus $cn @{ Status = 'Stop fehlgeschlagen'; Meldung = $r.Meldung }
                    $items.Add([pscustomobject]@{ Worker = $label; File = $r.Name; SizeMB = $null; Report = $null; Error = $r.Meldung })
                    continue
                }
                Set-ServerStatus $cn @{ ETL_MB = $r.SizeMB }
                $sess = $recSessions | Where-Object { $_.ComputerName -eq $cn } | Select-Object -First 1
                $localFile = Join-Path $runFolder $r.Name
                $report = $null; $err = $null
                try {
                    Set-ServerStatus $cn @{ Status = 'Kopiere...' }
                    Copy-Item -FromSession $sess -Path $r.Path -Destination $localFile -Force -ErrorAction Stop
                    if ($S.AnalyzeLocation -eq 'Remote' -or -not $localAvailable) {
                        if ($S.AnalyzeLocation -ne 'Remote') { Write-Log "Get-MpPerformanceReport lokal nicht verfuegbar – Auswertung auf $label." 'WARN' }
                        Set-ServerStatus $cn @{ Status = 'Auswertung (remote)...' }
                        $json = Invoke-Command -Session $sess -ScriptBlock ${function:Remote-Analyze} -ArgumentList $r.Path, $prm -ErrorAction Stop
                        $report = ($json -join '') | ConvertFrom-Json
                    }
                    else {
                        Set-ServerStatus $cn @{ Status = 'Auswertung...' }
                        $report = Get-ReportLocal -Path $localFile -Settings $S
                    }
                    if ($S.DeleteRemote) { Invoke-Command -Session $sess -ScriptBlock ${function:Remote-Delete} -ArgumentList $r.Path -ErrorAction SilentlyContinue }
                    Set-ServerStatus $cn @{ Status = 'Fertig'; Meldung = "ETL: $localFile" }
                    Write-Log "$label ausgewertet ($($r.SizeMB) MB)"
                }
                catch {
                    $err = ($_.Exception.Message -split "`n")[0]
                    Set-ServerStatus $cn @{ Status = 'Fehler'; Meldung = $err }
                    Write-Log "$label : $err" 'ERROR'
                }
                $items.Add([pscustomobject]@{ Worker = $label; File = $r.Name; SizeMB = $r.SizeMB; Report = $report; Error = $err; RecordMinutes = $actualMinutes })
            }
            $sync.Progress = 100
            if ($items.Count) { Complete-Analysis -Items $items.ToArray() -Settings $S -OutputFolder (Join-Path $runFolder 'Auswertung') }
        }
        finally {
            if ($sessions) { Remove-PSSession $sessions -ErrorAction SilentlyContinue }
            $sync.ProgressText = ''
        }
    }

    function Invoke-FolderAnalysis {
        param($A)
        $S = $A.Settings
        if (-not (Get-Command Get-MpPerformanceReport -ErrorAction SilentlyContinue)) {
            Write-Log 'Get-MpPerformanceReport ist auf diesem PC nicht verfuegbar (Defender-Plattform >= 4.18.2108.7 noetig).' 'ERROR'
            return
        }
        $files = @($A.Files)
        $outFolder = Join-Path (Split-Path $files[0]) ('Auswertung_{0:yyyy-MM-dd_HHmm}' -f (Get-Date))
        $sync.LogFile = $null
        Write-Log "Auswertung von $($files.Count) ETL-Datei(en) gestartet"
        $items = New-Object System.Collections.Generic.List[object]
        $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $i = 0
        foreach ($f in $files) {
            $i++
            if ($sync.Cancel) { Write-Log 'Auswertung abgebrochen.' 'WARN'; break }
            $fi = Get-Item -LiteralPath $f
            $base = $fi.BaseName
            $w = if ($base -match $S.WorkerRegex -and $Matches['Worker']) { $Matches['Worker'] } else { $base }
            $label = Get-UniqueLabel -Label $w.ToUpper() -Used $used
            $sync.Progress = [math]::Round(($i - 1) / $files.Count * 100, 0)
            $sync.ProgressText = "Werte aus: $label ($i/$($files.Count))"
            $report = $null; $err = $null
            try { $report = Get-ReportLocal -Path $fi.FullName -Settings $S; Write-Log "$label ausgewertet ($($fi.Name))" }
            catch { $err = ($_.Exception.Message -split "`n")[0]; Write-Log "$label : $err" 'ERROR' }
            $items.Add([pscustomobject]@{ Worker = $label; File = $fi.Name; SizeMB = [math]::Round($fi.Length / 1MB, 1); Report = $report; Error = $err })
        }
        $sync.Progress = 100
        $sync.ProgressText = ''
        if ($items.Count) { Complete-Analysis -Items $items.ToArray() -Settings $S -OutputFolder $outFolder }
    }

    #----- Defender-Features (Inventar pro Worker) -----

    function Get-SafeName {
        param([string]$Name)
        return ($Name -replace '[^\w\-]', '_')
    }

    function Remote-Inventory {
        # Laeuft auf dem Worker: liefert alle relevanten Defender-Einstellungen als Zeilen
        $rows = New-Object System.Collections.Generic.List[object]
        function Add-Row {
            param($Bereich, $Feature, $Wert, $Bewertung = 'OK', $Hinweis = '')
            $rows.Add([pscustomobject]@{ Bereich = $Bereich; Feature = $Feature; Wert = "$Wert"; Bewertung = $Bewertung; Hinweis = "$Hinweis" })
        }
        function Map {
            param($Value, [hashtable]$Table)
            if ($null -eq $Value -or "$Value" -eq '') { return '-' }
            try { $k = [int]$Value; if ($Table.ContainsKey($k)) { return $Table[$k] } } catch {}
            return "$Value"
        }
        function OnOff { param($b) if ($b) { 'Ein' } else { 'Aus' } }
        function Count-RegValues {
            param($Path)
            if (-not (Test-Path $Path)) { return 0 }
            $n = 0
            foreach ($k in @(Get-Item $Path) + @(Get-ChildItem $Path -Recurse -ErrorAction SilentlyContinue)) { $n += $k.ValueCount }
            return $n
        }
        function Expand-DlpBlob {
            param([byte[]]$Bytes)
            foreach ($off in 0, 2, 4, 6, 8, 12, 16) {
                if ($Bytes.Length -le $off + 2) { continue }
                foreach ($kind in 'Deflate', 'GZip') {
                    try {
                        $ms = New-Object System.IO.MemoryStream(, $Bytes)
                        $ms.Position = $off
                        $ds = if ($kind -eq 'Deflate') { New-Object System.IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress) }
                              else { New-Object System.IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress) }
                        $sr = New-Object System.IO.StreamReader($ds)
                        $t = $sr.ReadToEnd(); $sr.Dispose()
                        if ($t -match '^\s*[\{\[<]') { return $t }
                    } catch {}
                }
            }
            foreach ($enc in [Text.Encoding]::UTF8, [Text.Encoding]::Unicode) {
                $t = $enc.GetString($Bytes)
                if ($t -match '^\s*[\{\[<]') { return $t }
            }
            return $null
        }

        $asrNames = @{
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Missbrauch anfaelliger signierter Treiber blockieren'
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Adobe Reader: Kindprozesse blockieren'
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Office-Apps: Kindprozesse blockieren'
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Diebstahl von Anmeldeinformationen aus LSASS blockieren'
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Ausfuehrbare Inhalte aus E-Mail/Webmail blockieren'
            '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Ausfuehrbare Dateien ohne Verbreitung/Alter/Vertrauen blockieren'
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Verschleierte Skripte blockieren'
            'd3e037e1-3eb8-44c8-a917-57927947596d' = 'JS/VBS: Start heruntergeladener Inhalte blockieren'
            '3b576869-a4ec-4529-8536-b80a7769e899' = 'Office-Apps: Erstellen ausfuehrbarer Inhalte blockieren'
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Office-Apps: Code-Injektion blockieren'
            '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Office-Kommunikations-Apps: Kindprozesse blockieren'
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Persistenz ueber WMI-Ereignisabonnement blockieren'
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Prozesserstellung durch PSExec/WMI blockieren'
            '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Neustart im abgesicherten Modus blockieren'
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Nicht vertrauenswuerdige Prozesse von USB blockieren'
            'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Kopierte/imitierte Systemtools blockieren'
            'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Webshell-Erstellung auf Servern blockieren'
            '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Win32-API-Aufrufe aus Office-Makros blockieren'
            'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Erweiterter Ransomware-Schutz'
        }

        $isServer = $false
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $isServer = ($os.ProductType -ne 1)
            Add-Row 'System' 'Betriebssystem' ('{0} (Build {1})' -f $os.Caption, $os.BuildNumber) 'Info'
        } catch {}

        $st = $null; $pr = $null
        try { $st = Get-MpComputerStatus -ErrorAction Stop } catch { Add-Row 'Antivirus' 'Get-MpComputerStatus' $_.Exception.Message 'Fehler' }
        try { $pr = Get-MpPreference -ErrorAction Stop } catch { Add-Row 'Antivirus' 'Get-MpPreference' $_.Exception.Message 'Fehler' }

        if ($st) {
            $mode = "$($st.AMRunningMode)"
            $ev = switch -Regex ($mode) { '^Normal' { 'OK' } 'EDR' { 'Info' } 'Passive' { 'Warnung' } default { 'Info' } }
            Add-Row 'Antivirus' 'Betriebsmodus' $mode $ev $(if ($ev -eq 'Warnung') { 'Defender AV ist nicht der primaere Virenschutz' })
            Add-Row 'Antivirus' 'Plattform-Version' $st.AMProductVersion 'Info'
            Add-Row 'Antivirus' 'Engine-Version' $st.AMEngineVersion 'Info'
            Add-Row 'Antivirus' 'Signatur-Version' $st.AntivirusSignatureVersion 'Info'
            $age = $null
            if ($st.AntivirusSignatureLastUpdated) { $age = [math]::Round(((Get-Date) - $st.AntivirusSignatureLastUpdated).TotalDays, 1) }
            Add-Row 'Antivirus' 'Signaturalter (Tage)' $age $(if ($age -gt 3) { 'Warnung' } else { 'OK' }) $(if ($age -gt 3) { 'Signaturen aelter als 3 Tage' })
            Add-Row 'Antivirus' 'Echtzeitschutz' (OnOff $st.RealTimeProtectionEnabled) $(if ($st.RealTimeProtectionEnabled) { 'OK' } else { 'Warnung' })
            Add-Row 'Antivirus' 'Verhaltensueberwachung' (OnOff $st.BehaviorMonitorEnabled) $(if ($st.BehaviorMonitorEnabled) { 'OK' } else { 'Warnung' })
            Add-Row 'Antivirus' 'Downloads/Anhaenge scannen (IOAV)' (OnOff $st.IoavProtectionEnabled) $(if ($st.IoavProtectionEnabled) { 'OK' } else { 'Warnung' })
            Add-Row 'Antivirus' 'On-Access-Schutz' (OnOff $st.OnAccessProtectionEnabled) $(if ($st.OnAccessProtectionEnabled) { 'OK' } else { 'Warnung' })
            Add-Row 'Antivirus' 'Netzwerkinspektion (NIS)' (OnOff $st.NISEnabled) 'Info'
            Add-Row 'Antivirus' 'Manipulationsschutz' (OnOff $st.IsTamperProtected) $(if ($st.IsTamperProtected) { 'OK' } else { 'Warnung' }) ('Quelle: {0}' -f $st.TamperProtectionSource)
            Add-Row 'System' 'Virtuelle Maschine' (OnOff $st.IsVirtualMachine) 'Info'
            if ($st.QuickScanEndTime) { Add-Row 'Scans' 'Letzter Quick-Scan' ('{0:dd.MM.yyyy HH:mm}' -f $st.QuickScanEndTime) 'Info' }
        }

        if ($pr) {
            Add-Row 'Cloud' 'Cloud-Schutz (MAPS)' (Map $pr.MAPSReporting @{ 0 = 'Aus'; 1 = 'Basic'; 2 = 'Advanced' }) $(if ($pr.MAPSReporting -eq 0) { 'Warnung' } else { 'OK' })
            Add-Row 'Cloud' 'Sample-Uebermittlung' (Map $pr.SubmitSamplesConsent @{ 0 = 'Immer fragen'; 1 = 'Sichere Samples automatisch'; 2 = 'Nie'; 3 = 'Alle automatisch' }) 'Info'
            Add-Row 'Cloud' 'Cloud-Blockstufe' (Map $pr.CloudBlockLevel @{ 0 = 'Standard'; 1 = 'Moderat'; 2 = 'Hoch'; 4 = 'Hoch+'; 6 = 'Null-Toleranz' }) 'Info'
            Add-Row 'Cloud' 'Erweitertes Cloud-Timeout (s)' $pr.CloudExtendedTimeout 'Info'
            Add-Row 'Schutz' 'PUA-Schutz' (Map $pr.PUAProtection @{ 0 = 'Aus'; 1 = 'Blockieren'; 2 = 'Ueberwachen' }) $(if ($pr.PUAProtection -eq 0) { 'Info' } else { 'OK' })
            Add-Row 'Schutz' 'Netzwerkschutz' (Map $pr.EnableNetworkProtection @{ 0 = 'Aus'; 1 = 'Blockieren'; 2 = 'Ueberwachen' }) $(if ($pr.EnableNetworkProtection -eq 1) { 'OK' } elseif ($pr.EnableNetworkProtection -eq 2) { 'Info' } else { 'Warnung' })
            if ($isServer) { Add-Row 'Schutz' 'Netzwerkschutz auf Server erlaubt' (OnOff $pr.AllowNetworkProtectionOnWinServer) $(if ($pr.AllowNetworkProtectionOnWinServer) { 'OK' } else { 'Info' }) }
            Add-Row 'Schutz' 'Ueberwachter Ordnerzugriff' (Map $pr.EnableControlledFolderAccess @{ 0 = 'Aus'; 1 = 'Blockieren'; 2 = 'Ueberwachen'; 3 = 'Nur Datentraeger blockieren'; 4 = 'Nur Datentraeger ueberwachen' }) 'Info'
            Add-Row 'Schutz' 'Datei-Hash-Berechnung' (OnOff $pr.EnableFileHashComputation) 'Info'
            Add-Row 'Scan-Optionen' 'Script-Scanning' (OnOff (-not $pr.DisableScriptScanning)) $(if ($pr.DisableScriptScanning) { 'Warnung' } else { 'OK' })
            Add-Row 'Scan-Optionen' 'Archiv-Scan' (OnOff (-not $pr.DisableArchiveScanning)) 'Info'
            Add-Row 'Scan-Optionen' 'E-Mail-Scan' (OnOff (-not $pr.DisableEmailScanning)) 'Info'
            Add-Row 'Scan-Optionen' 'Echtzeit-Scanrichtung' (Map $pr.RealTimeScanDirection @{ 0 = 'Ein- und ausgehend'; 1 = 'Nur eingehend'; 2 = 'Nur ausgehend' }) 'Info'
            Add-Row 'Scan-Optionen' 'Max. CPU-Last Scan (%)' $pr.ScanAvgCPULoadFactor 'Info'
            Add-Row 'Scan-Optionen' 'Niedrige CPU-Prioritaet' (OnOff $pr.EnableLowCpuPriority) 'Info'
            $day = Map $pr.ScanScheduleDay @{ 0 = 'Taeglich'; 1 = 'Sonntag'; 2 = 'Montag'; 3 = 'Dienstag'; 4 = 'Mittwoch'; 5 = 'Donnerstag'; 6 = 'Freitag'; 7 = 'Samstag'; 8 = 'Nie' }
            $sched = ('{0}, {1}, {2}' -f (Map $pr.ScanParameters @{ 1 = 'Quick'; 2 = 'Full' }), $day, $pr.ScanScheduleTime)
            Add-Row 'Scans' 'Geplanter Scan' $sched $(if ($pr.ScanScheduleDay -ne 8) { 'Info' } else { 'OK' }) $(if ($pr.ScanScheduleDay -ne 8) { 'Geplante Scans auf non-persistent Workern pruefen' })
            Add-Row 'Scans' 'Nur scannen wenn inaktiv' (OnOff $pr.ScanOnlyIfIdleEnabled) 'Info'
            Add-Row 'Scans' 'Catch-up Quick-Scan' (OnOff (-not $pr.DisableCatchupQuickScan)) 'Info'
            Add-Row 'Updates' 'Signatur-Update-Intervall (h)' $pr.SignatureUpdateInterval 'Info'
            Add-Row 'Updates' 'Shared Security Intelligence (VDI)' $(if ($pr.SharedSignaturesPath) { $pr.SharedSignaturesPath } else { 'nicht konfiguriert' }) $(if ($pr.SharedSignaturesPath) { 'OK' } else { 'Info' }) $(if (-not $pr.SharedSignaturesPath) { 'Fuer non-persistent VDI empfohlen' })
            Add-Row 'Updates' 'Signatur-Fallback-Reihenfolge' $pr.SignatureFallbackOrder 'Info'
            Add-Row 'Verwaltung' 'Lokale Admin-Einstellungen zusammenfuehren' (OnOff (-not $pr.DisableLocalAdminMerge)) 'Info'

            foreach ($ex in @(@('Pfade', $pr.ExclusionPath), @('Dateiendungen', $pr.ExclusionExtension), @('Prozesse', $pr.ExclusionProcess))) {
                $list = @($ex[1] | Where-Object { $_ })
                Add-Row 'Ausschluesse' $ex[0] ($list -join '; ') 'Info' ('{0} Eintraege' -f $list.Count)
            }
            $vhdOk = (@(@($pr.ExclusionExtension) -match '^\.?vhdx?$').Count -gt 0) -or (@(@($pr.ExclusionPath) -match '\.vhdx?').Count -gt 0)
            Add-Row 'Ausschluesse' 'FSLogix VHD/VHDX ausgeschlossen' $(if ($vhdOk) { 'Ja' } else { 'Nein' }) $(if ($vhdOk) { 'OK' } else { 'Warnung' }) $(if (-not $vhdOk) { 'Empfehlung: *.vhd/*.vhdx bzw. FSLogix-Container-Pfade ausschliessen' })

            $ids = @($pr.AttackSurfaceReductionRules_Ids)
            $acts = @($pr.AttackSurfaceReductionRules_Actions)
            $seen = @{}
            for ($i = 0; $i -lt $ids.Count; $i++) {
                if (-not $ids[$i]) { continue }
                $id = "$($ids[$i])".ToLower()
                $seen[$id] = $true
                $name = if ($asrNames.ContainsKey($id)) { $asrNames[$id] } else { $id }
                $a = if ($i -lt $acts.Count) { $acts[$i] } else { $null }
                Add-Row 'ASR-Regeln' $name (Map $a @{ 0 = 'Aus'; 1 = 'Blockieren'; 2 = 'Ueberwachen'; 6 = 'Warnen' }) $(if ($a -eq 1) { 'OK' } else { 'Info' }) $id
            }
            foreach ($id in $asrNames.Keys) {
                if (-not $seen.ContainsKey($id)) { Add-Row 'ASR-Regeln' $asrNames[$id] 'Nicht konfiguriert' 'Info' $id }
            }
            Add-Row 'ASR-Regeln' 'ASR-Ausschluesse' (@($pr.AttackSurfaceReductionOnlyExclusions | Where-Object { $_ }) -join '; ') 'Info'
        }

        $sense = Get-Service -Name Sense -ErrorAction SilentlyContinue
        Add-Row 'Defender for Endpoint' 'Sense-Dienst' $(if ($sense) { "$($sense.Status)" } else { 'nicht installiert' }) $(if ($sense -and "$($sense.Status)" -eq 'Running') { 'OK' } else { 'Warnung' })
        $stKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
        Add-Row 'Defender for Endpoint' 'Onboarding-Status' $(if ($stKey.OnboardingState -eq 1) { 'Onboardet' } else { 'Nicht onboardet' }) $(if ($stKey.OnboardingState -eq 1) { 'OK' } else { 'Warnung' })
        if ($stKey.OrgId) { Add-Row 'Defender for Endpoint' 'Org-ID' $stKey.OrgId 'Info' }
        $tag = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging' -ErrorAction SilentlyContinue).Group
        Add-Row 'Defender for Endpoint' 'Geraete-Tag' $(if ($tag) { $tag } else { '-' }) 'Info'
        $passive = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -ErrorAction SilentlyContinue).ForceDefenderPassiveMode
        Add-Row 'Defender for Endpoint' 'Passivmodus erzwungen' $(if ($passive -eq 1) { 'Ja' } else { 'Nein' }) 'Info'

        Add-Row 'Verwaltung' 'Werte per Richtlinie (GPO)' (Count-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender') 'Info' 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
        Add-Row 'Verwaltung' 'Werte per MDM/Intune' (Count-RegValues 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender') 'Info' 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Defender'

        try {
            foreach ($fw in Get-NetFirewallProfile -ErrorAction Stop) {
                $on = "$($fw.Enabled)" -eq 'True'
                Add-Row 'Firewall' ('Profil {0}' -f $fw.Name) (OnOff $on) $(if ($on) { 'OK' } else { 'Warnung' })
            }
        } catch {}

        $dprops = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender' -ErrorAction SilentlyContinue
        $dlpProps = @()
        if ($dprops) { $dlpProps = @($dprops.PSObject.Properties | Where-Object { $_.Name -match '^dlp' }) }
        Add-Row 'Endpoint DLP (Geraet)' 'DLP-Policy auf Geraet' $(if ($dlpProps.Count) { 'Ja' } else { 'Nein' }) $(if ($dlpProps.Count) { 'OK' } else { 'Info' }) $(if (-not $dlpProps.Count) { 'Keine dlp*-Werte gefunden (keine Endpoint-DLP-Policy oder Geraet nicht onboardet)' })
        foreach ($p in $dlpProps) {
            $v = $p.Value; $size = 0; $text = $null
            if ($v -is [byte[]]) { $size = $v.Length; $text = Expand-DlpBlob $v }
            elseif ($v -is [string]) { $size = $v.Length; if ($v -match '^\s*[\{\[<]') { $text = $v } }
            $names = @()
            if ($text) {
                $names = @([regex]::Matches($text, '"(?:[Pp]olicy[Nn]ame|[Rr]ule[Nn]ame|[Nn]ame)"\s*:\s*"([^"]{2,120})"') |
                    ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique -First 30)
            }
            $wert = '{0:N0} Bytes; dekodiert: {1}' -f $size, $(if ($text) { 'ja' } else { 'nein' })
            if ($names.Count) { $wert += '; Namen: ' + ($names -join ', ') }
            Add-Row 'Endpoint DLP (Geraet)' $p.Name $wert 'Info' 'Undokumentiertes Format, Dekodierung best effort'
        }

        return $rows.ToArray()
    }

    function Get-WorstRating {
        param([string[]]$Ratings)
        foreach ($r in 'Fehler', 'Warnung', 'Info', 'OK') { if ($Ratings -contains $r) { return $r } }
        return 'OK'
    }

    function Build-FeatureViews {
        param([object[]]$Rows, [string[]]$Workers)
        # Matrix: eine Zeile pro Feature, eine Spalte pro Worker
        $order = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($r in $Rows) {
            $k = "$($r.Bereich)|$($r.Feature)"
            if (-not $order.Contains($k)) { $order[$k] = New-Object System.Collections.Generic.List[object] }
            $order[$k].Add($r)
        }
        $matrix = foreach ($k in $order.Keys) {
            $grp = $order[$k]
            $o = [ordered]@{ Bereich = $grp[0].Bereich; Feature = $grp[0].Feature }
            $vals = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($w in $Workers) {
                $row = $grp | Where-Object Worker -eq $w | Select-Object -First 1
                $v = if ($row) { $row.Wert } else { '—' }
                [void]$vals.Add($v)
                $o[(Get-SafeName $w)] = $v
            }
            $worst = Get-WorstRating @($grp | ForEach-Object Bewertung)
            $diff = $vals.Count -gt 1
            $o['Abweichung'] = $(if ($diff) { 'ja' } else { '' })
            $o['Bewertung'] = $(if ($worst -in 'Fehler', 'Warnung') { $worst } elseif ($diff) { 'Abweichung' } else { $worst })
            [pscustomobject]$o
        }

        # Uebersicht pro Worker
        $overview = foreach ($w in $Workers) {
            $wr = @($Rows | Where-Object Worker -eq $w)
            $get = { param($f) ($wr | Where-Object Feature -eq $f | Select-Object -First 1).Wert }
            $warn = @($wr | Where-Object Bewertung -eq 'Warnung').Count
            $err  = @($wr | Where-Object Bewertung -eq 'Fehler').Count
            [pscustomobject][ordered]@{
                Worker               = $w
                Warnungen            = $warn
                Fehler               = $err
                Betriebsmodus        = & $get 'Betriebsmodus'
                Plattform            = & $get 'Plattform-Version'
                Signaturalter_Tage   = & $get 'Signaturalter (Tage)'
                Echtzeitschutz       = & $get 'Echtzeitschutz'
                Manipulationsschutz  = & $get 'Manipulationsschutz'
                Cloudschutz          = & $get 'Cloud-Schutz (MAPS)'
                Netzwerkschutz       = & $get 'Netzwerkschutz'
                ASR_Block            = @($wr | Where-Object { $_.Bereich -eq 'ASR-Regeln' -and $_.Wert -eq 'Blockieren' }).Count
                ASR_Audit            = @($wr | Where-Object { $_.Bereich -eq 'ASR-Regeln' -and $_.Wert -eq 'Ueberwachen' }).Count
                VHDX_ausgeschlossen  = & $get 'FSLogix VHD/VHDX ausgeschlossen'
                MDE_Onboarding       = & $get 'Onboarding-Status'
                GPO_Werte            = & $get 'Werte per Richtlinie (GPO)'
                MDM_Werte            = & $get 'Werte per MDM/Intune'
                DLP_Policy_Geraet    = & $get 'DLP-Policy auf Geraet'
                Bewertung            = $(if ($err) { 'Fehler' } elseif ($warn) { 'Warnung' } else { 'OK' })
            }
        }
        @{
            List     = @($Rows)
            Matrix   = @($matrix)
            Overview = @($overview)
            Workers  = $Workers
            Created  = Get-Date
        }
    }

    function Invoke-FeatureInventory {
        param($A)
        $S = $A.Settings
        Write-Log "Defender-Features: Inventar fuer $($A.Servers.Count) Server gestartet"
        foreach ($srv in $A.Servers) { Set-ServerStatus $srv @{ Status = 'Verbinde...' } }
        $sessions = @(Open-Sessions -Servers $A.Servers -Settings $S -Credential $A.Credential)
        if (-not $sessions) { Write-Log 'Keine Verbindung zu einem Server moeglich.' 'ERROR'; return }
        try {
            $sync.ProgressText = 'Lese Defender-Einstellungen...'
            foreach ($sx in $sessions) { Set-ServerStatus $sx.ComputerName @{ Status = 'Lese Features...' } }
            $res = Invoke-OnSessions -Sessions $sessions -Block ${function:Remote-Inventory} -ArgList @() -Settings $S
            $rows = New-Object System.Collections.Generic.List[object]
            $workers = New-Object System.Collections.Generic.List[string]
            $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($grp in ($res | Group-Object PSComputerName)) {
                $label = Get-UniqueLabel -Label (Get-ShortName $grp.Name) -Used $used
                $workers.Add($label)
                foreach ($r in $grp.Group) {
                    $rows.Add([pscustomobject]@{ Worker = $label; Bereich = $r.Bereich; Feature = $r.Feature; Wert = $r.Wert; Bewertung = $r.Bewertung; Hinweis = $r.Hinweis })
                }
                $w = @($grp.Group | Where-Object Bewertung -eq 'Warnung').Count
                $plat = ($grp.Group | Where-Object Feature -eq 'Plattform-Version' | Select-Object -First 1).Wert
                Set-ServerStatus $grp.Name @{ Status = 'Features eingelesen'; Plattform = $plat; Meldung = "$w Warnung(en)" }
            }
            if ($workers.Count) {
                $sync.FeatResults = Build-FeatureViews -Rows $rows.ToArray() -Workers $workers.ToArray()
                $sync.FeatReady = $true
                Write-Log "Defender-Features eingelesen: $($workers.Count) Worker, $($rows.Count) Werte"
            }
        }
        finally {
            Remove-PSSession $sessions -ErrorAction SilentlyContinue
            $sync.ProgressText = ''
        }
    }

    #----- DLP-Richtlinien aus Purview -----

    function Get-NamesDeep {
        # Sammelt "name"-Werte aus verschachtelten Hashtables/Arrays/Strings (SITs, Labels)
        param($Object, [int]$Depth = 0)
        if ($null -eq $Object -or $Depth -gt 8) { return }
        if ($Object -is [string]) {
            foreach ($m in [regex]::Matches($Object, '(?i)\bname\s*[=:]\s*"?([^;"}\r\n,]+)')) { $m.Groups[1].Value.Trim() }
            return
        }
        if ($Object -is [System.Collections.IDictionary]) {
            foreach ($k in $Object.Keys) {
                if ("$k" -ieq 'name') { "$($Object[$k])" }
                elseif ($Object[$k] -isnot [ValueType]) { Get-NamesDeep $Object[$k] ($Depth + 1) }
            }
            return
        }
        if ($Object -is [System.Collections.IEnumerable]) {
            foreach ($o in $Object) { Get-NamesDeep $o ($Depth + 1) }
            return
        }
        if ($Object -is [psobject]) {
            foreach ($p in $Object.PSObject.Properties) {
                if ($p.Name -ieq 'name') { "$($p.Value)" }
                elseif ($p.Value -isnot [ValueType]) { Get-NamesDeep $p.Value ($Depth + 1) }
            }
        }
    }

    function Get-DlpConditionSummary {
        param($Rule)
        $parts = New-Object System.Collections.Generic.List[string]
        $sit = @(Get-NamesDeep $Rule.ContentContainsSensitiveInformation | Where-Object { $_ } | Select-Object -Unique)
        if ($sit.Count) { $parts.Add('Inhalt: ' + ($sit -join ', ')) }
        $exSit = @(Get-NamesDeep $Rule.ExceptIfContentContainsSensitiveInformation | Where-Object { $_ } | Select-Object -Unique)
        if ($exSit.Count) { $parts.Add('Ausnahme: ' + ($exSit -join ', ')) }
        if ($Rule.AdvancedRule) {
            $adv = @([regex]::Matches("$($Rule.AdvancedRule)", '"[Nn]ame"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
            if ($adv.Count) { $parts.Add('Erweiterte Bedingung: ' + ($adv -join ', ')) } else { $parts.Add('Erweiterte Bedingung (siehe Details)') }
        }
        $handled = 'ContentContainsSensitiveInformation', 'ExceptIfContentContainsSensitiveInformation', 'AdvancedRule'
        foreach ($p in $Rule.PSObject.Properties) {
            if ($handled -contains $p.Name) { continue }
            if ($p.Name -notmatch '^(ExceptIf)?(Content|Document|FileExtension|AccessScope|From|SentTo|Recipient|Sender|Subject|Attachment|Processing)') { continue }
            $v = $p.Value
            if ($null -eq $v -or "$v" -eq '' -or "$v" -eq 'False' -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and @($v).Count -eq 0)) { continue }
            $txt = if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { (@($v) | ForEach-Object { "$_" }) -join ', ' } else { "$v" }
            if ($txt.Length -gt 80) { $txt = $txt.Substring(0, 77) + '...' }
            $parts.Add("$($p.Name)=$txt")
        }
        return ($parts -join ' | ')
    }

    function Format-EndpointRestrictions {
        param($Value)
        $out = foreach ($r in @($Value)) {
            if ($null -eq $r) { continue }
            if ($r -is [System.Collections.IDictionary]) {
                $set = $null; $val = $null
                foreach ($k in $r.Keys) { if ("$k" -ieq 'setting') { $set = $r[$k] } elseif ("$k" -ieq 'value') { $val = $r[$k] } }
                if ($set) { "$set=$val" } else { ($r.Keys | ForEach-Object { "$_=$($r[$_])" }) -join ',' }
            }
            else {
                $s = "$r"
                if ($s -match '(?i)setting\s*=\s*([^;}]+).*?value\s*=\s*([^;}]+)') { "$($Matches[1].Trim())=$($Matches[2].Trim())" } else { $s.Trim('@{}') }
            }
        }
        return (@($out) -join '; ')
    }

    function ConvertTo-ModeText {
        param([string]$Mode)
        switch ($Mode) {
            'Enable'                   { 'Erzwingen' }
            'TestWithNotifications'    { 'Simulation mit Richtlinientipps' }
            'TestWithoutNotifications' { 'Simulation' }
            'Disable'                  { 'Aus' }
            default                    { $Mode }
        }
    }

    function ConvertTo-RawText {
        param($Object)
        try { return ($Object | Select-Object * | ConvertTo-Json -Depth 5) }
        catch { return ($Object | Format-List * | Out-String) }
    }

    function Invoke-DlpInventory {
        param($A)
        $S = $A.Settings
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Log 'Modul ExchangeOnlineManagement fehlt. Installation: Install-Module ExchangeOnlineManagement -Scope CurrentUser' 'ERROR'
            return
        }
        $sync.ProgressText = 'Verbinde mit Purview (Security & Compliance)...'
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $cmd = Get-Command Connect-IPPSSession
        $p = @{ ErrorAction = 'Stop' }
        if ($S.Upn) { $p.UserPrincipalName = $S.Upn }
        if ($cmd.Parameters.ContainsKey('ShowBanner')) { $p.ShowBanner = $false }
        if ($S.DisableWam -and $cmd.Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
        Write-Log 'Anmeldung an Security & Compliance PowerShell (Anmeldefenster beachten)...'
        Connect-IPPSSession @p
        try {
            $sync.ProgressText = 'Lese DLP-Richtlinien und -Regeln...'
            $policies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
            $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
            Write-Log "Purview: $($policies.Count) DLP-Richtlinie(n), $($rules.Count) Regel(n) gefunden"

            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($pol in ($policies | Sort-Object Priority)) {
                $isEndpoint = (@($pol.EndpointDlpLocation | Where-Object { $_ }).Count -gt 0) -or ("$($pol.Workload)" -match 'Endpoint')
                if ($S.EndpointOnly -and -not $isEndpoint) { continue }
                $scope = @($pol.EndpointDlpLocation | ForEach-Object { "$_" } | Where-Object { $_ })
                $scopeEx = @($pol.EndpointDlpLocationException | ForEach-Object { "$_" } | Where-Object { $_ })
                $modeText = ConvertTo-ModeText "$($pol.Mode)"
                $polRules = @($rules | Where-Object { "$($_.ParentPolicyName)" -eq "$($pol.Name)" -or "$($_.Policy)" -eq "$($pol.Guid)" -or "$($_.Policy)" -eq "$($pol.Identity)" } | Sort-Object Priority)
                if (-not $polRules.Count) { $polRules = @($null) }
                foreach ($r in $polRules) {
                    $ruleOn = $r -and -not $r.Disabled
                    $bew = if (-not $pol.Enabled -or "$($pol.Mode)" -eq 'Disable' -or ($r -and $r.Disabled)) { 'Aus' }
                           elseif ("$($pol.Mode)" -match '^Test') { 'Info' } else { 'OK' }
                    $raw = "=== Richtlinie ===`n" + (ConvertTo-RawText $pol)
                    if ($r) { $raw += "`n`n=== Regel ===`n" + (ConvertTo-RawText $r) }
                    $rows.Add([pscustomobject][ordered]@{
                        Richtlinie          = $pol.Name
                        Modus               = $modeText
                        Richtlinie_aktiv    = $(if ($pol.Enabled) { 'Ja' } else { 'Nein' })
                        Workloads           = "$($pol.Workload)"
                        Endpoint_Bereich    = $(if ($scope.Count) { $scope -join ', ' } elseif ($isEndpoint) { 'Alle' } else { '-' })
                        Endpoint_Ausnahmen  = ($scopeEx -join ', ')
                        Prio_Richtlinie     = $pol.Priority
                        Regel               = $(if ($r) { $r.Name } else { '(keine Regeln)' })
                        Regel_aktiv         = $(if ($r) { if ($ruleOn) { 'Ja' } else { 'Nein' } } else { '-' })
                        Prio_Regel          = $(if ($r) { $r.Priority } else { $null })
                        Bedingungen         = $(if ($r) { Get-DlpConditionSummary $r } else { '' })
                        Endpoint_Aktionen   = $(if ($r) { Format-EndpointRestrictions $r.EndpointDlpRestrictions } else { '' })
                        Zugriff_blockieren  = $(if ($r) { "$($r.BlockAccess)" } else { '' })
                        Benachrichtigung    = $(if ($r) { (@($r.NotifyUser) | ForEach-Object { "$_" }) -join ', ' } else { '' })
                        Schweregrad         = $(if ($r) { "$($r.ReportSeverityLevel)" } else { '' })
                        Verteilung          = "$($pol.DistributionStatus)"
                        Geaendert           = $(if ($r -and $r.WhenChanged) { '{0:dd.MM.yyyy HH:mm}' -f $r.WhenChanged } elseif ($pol.WhenChanged) { '{0:dd.MM.yyyy HH:mm}' -f $pol.WhenChanged } else { '' })
                        Bewertung           = $bew
                        Raw                 = $raw
                    })
                }
            }

            try {
                $cfg = Get-PolicyConfig -ErrorAction Stop
                $rows.Add([pscustomobject][ordered]@{
                    Richtlinie = '(Globale Endpoint-DLP-Einstellungen)'; Modus = ''; Richtlinie_aktiv = ''; Workloads = 'EndpointDevices'
                    Endpoint_Bereich = ''; Endpoint_Ausnahmen = ''; Prio_Richtlinie = $null; Regel = 'Get-PolicyConfig'; Regel_aktiv = ''
                    Prio_Regel = $null; Bedingungen = 'Ausschluesse, eingeschraenkte Apps, Browser, Druckergruppen usw. (siehe Details)'
                    Endpoint_Aktionen = ''; Zugriff_blockieren = ''; Benachrichtigung = ''; Schweregrad = ''; Verteilung = ''; Geaendert = ''
                    Bewertung = 'Info'; Raw = (ConvertTo-RawText $cfg)
                })
            }
            catch { Write-Log "Globale Endpoint-DLP-Einstellungen nicht lesbar: $($_.Exception.Message)" 'WARN' }

            $sync.DlpResults = $rows.ToArray()
            $sync.DlpReady = $true
            Write-Log "DLP-Regeln eingelesen: $($rows.Count) Zeile(n)$(if ($S.EndpointOnly) { ' (nur Endpoint-DLP)' })"
        }
        finally {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            $sync.ProgressText = ''
        }
    }

    #----- Ressourcenmessung: Defender im Vergleich zu allen anderen Prozessen -----

    function Remote-ResourceSample {
        # Laeuft auf dem Worker: misst periodisch CPU, RAM (privater Working Set) und I/O aller Prozesse
        # (sprachunabhaengig ueber Win32_PerfRawData_PerfProc_Process) und liefert flache Objekte:
        # Tick (pro Intervall), SnapProc/SnapCat/SnapTot (kumulierte Zwischenstaende)
        param([double]$Minutes, [int]$IntervalSec, [string[]]$CatNames, [string[]]$CatRegex, [int]$TopN, [int]$SnapshotSec)
        $cores = [Environment]::ProcessorCount
        $myPid = $PID
        $allCats = @($CatNames) + 'Sonstige'
        $catCache = @{}
        function Get-Cat {
            param([string]$n)
            if ($catCache.ContainsKey($n)) { return $catCache[$n] }
            $c = 'Sonstige'
            for ($i = 0; $i -lt $CatNames.Count; $i++) { if ($CatRegex[$i] -and $n -match $CatRegex[$i]) { $c = $CatNames[$i]; break } }
            $catCache[$n] = $c
            return $c
        }
        $agg = @{}
        $catAgg = @{}
        foreach ($c in $allCats) { $catAgg[$c] = @{ Cpu = 0.0; Io = 0.0; WsSum = 0.0 } }
        $tot = @{ Cpu = 0.0; Io = 0.0; WsSum = 0.0; Own = 0.0; Elapsed = 0.0; Samples = 0 }

        function Emit-Snapshot {
            param([bool]$Final, [int]$No)
            $div = [math]::Max($tot.Samples, 1)
            $procs = foreach ($k in $agg.Keys) {
                $a = $agg[$k]
                [pscustomobject]@{ Name = $k; Kategorie = $a.Cat; Cpu = $a.Cpu; Io = $a.Io; WsAvg = $a.WsSum / $div; MaxCpuPct = $a.MaxPct; MaxInst = $a.MaxInst }
            }
            $top = @($procs | Sort-Object Cpu -Descending | Select-Object -First ([math]::Max($TopN, 10)))
            $def = @($procs | Where-Object { $_.Kategorie -eq $CatNames[0] })
            foreach ($p in @($top + $def | Sort-Object Name -Unique)) {
                [pscustomobject]@{ Kind = 'SnapProc'; Snap = $No; Name = $p.Name; Kategorie = $p.Kategorie; Cpu = $p.Cpu; Io = $p.Io; WsAvg = $p.WsAvg; MaxCpuPct = $p.MaxCpuPct; MaxInst = $p.MaxInst }
            }
            foreach ($c in $allCats) {
                [pscustomobject]@{ Kind = 'SnapCat'; Snap = $No; Kategorie = $c; Cpu = $catAgg[$c].Cpu; Io = $catAgg[$c].Io; WsAvg = $catAgg[$c].WsSum / $div }
            }
            [pscustomobject]@{
                Kind = 'SnapTot'; Snap = $No; Final = $Final; Cores = $cores; Samples = $tot.Samples; Elapsed100ns = $tot.Elapsed
                TotalCpu = $tot.Cpu; TotalIo = $tot.Io; TotalWsAvg = $tot.WsSum / $div; OwnCpu = $tot.Own; ProcessCount = $agg.Count
            }
        }

        $props = 'Name', 'IDProcess', 'PercentProcessorTime', 'Timestamp_Sys100NS', 'WorkingSetPrivate', 'IODataBytesPersec'
        $prev = $null; $prevTs = $null
        $end = (Get-Date).AddMinutes($Minutes)
        $lastSnap = Get-Date
        $snapNo = 0
        while ($true) {
            $t0 = Get-Date
            $raw = @(Get-CimInstance -ClassName Win32_PerfRawData_PerfProc_Process -Property $props -ErrorAction Stop)
            $cur = @{}
            $totalTs = $null
            foreach ($r in $raw) {
                if ($r.Name -eq '_Total') { $totalTs = [double]$r.Timestamp_Sys100NS; continue }
                if ($r.Name -eq 'Idle') { continue }
                $cur["$($r.Name)|$($r.IDProcess)"] = $r
            }
            if ($prev -and $totalTs -and $prevTs -and ($totalTs - $prevTs) -gt 0) {
                $el = $totalTs - $prevTs
                $tickCats = New-Object double[] ($allCats.Count)
                $tickTotal = 0.0
                $nameCpu = @{}; $nameInst = @{}
                foreach ($k in $cur.Keys) {
                    $r = $cur[$k]; $p = $prev[$k]
                    $dc = 0.0; $di = 0.0
                    if ($p) {
                        $dc = [double]$r.PercentProcessorTime - [double]$p.PercentProcessorTime
                        $di = [double]$r.IODataBytesPersec - [double]$p.IODataBytesPersec
                        if ($dc -lt 0) { $dc = 0.0 }
                        if ($di -lt 0) { $di = 0.0 }
                    }
                    if ([int]$r.IDProcess -eq $myPid) { $tot.Own += $dc; continue }   # Messprozess selbst nicht mitzaehlen
                    $name = $r.Name -replace '#\d+$', ''
                    $ws = [double]$r.WorkingSetPrivate
                    $cat = Get-Cat $name
                    $ci = [array]::IndexOf($allCats, $cat)
                    $tickCats[$ci] += $dc
                    $tickTotal += $dc
                    $catAgg[$cat].Cpu += $dc; $catAgg[$cat].Io += $di; $catAgg[$cat].WsSum += $ws
                    $tot.Cpu += $dc; $tot.Io += $di; $tot.WsSum += $ws
                    if (-not $agg.ContainsKey($name)) { $agg[$name] = @{ Cat = $cat; Cpu = 0.0; Io = 0.0; WsSum = 0.0; MaxPct = 0.0; MaxInst = 0 } }
                    $a = $agg[$name]; $a.Cpu += $dc; $a.Io += $di; $a.WsSum += $ws
                    $nameCpu[$name] = [double]$nameCpu[$name] + $dc
                    $nameInst[$name] = [int]$nameInst[$name] + 1
                }
                foreach ($n in $nameCpu.Keys) {
                    $a = $agg[$n]
                    $pct = $nameCpu[$n] / ($el * $cores) * 100
                    if ($pct -gt $a.MaxPct) { $a.MaxPct = $pct }
                    if ($nameInst[$n] -gt $a.MaxInst) { $a.MaxInst = $nameInst[$n] }
                }
                $tot.Elapsed += $el
                $tot.Samples++
                $o = [ordered]@{ Kind = 'Tick'; Time = Get-Date; Cores = $cores; CpuTotalPct = $tickTotal / ($el * $cores) * 100 }
                for ($i = 0; $i -lt $allCats.Count; $i++) { $o["C$i"] = $tickCats[$i] / ($el * $cores) * 100 }
                [pscustomobject]$o
            }
            $prev = $cur; $prevTs = $totalTs
            if ($tot.Samples -gt 0 -and ((Get-Date) - $lastSnap).TotalSeconds -ge $SnapshotSec) {
                Emit-Snapshot -Final $false -No $snapNo
                $snapNo++
                $lastSnap = Get-Date
            }
            if ((Get-Date) -ge $end) { break }
            $sleep = $IntervalSec * 1000 - ((Get-Date) - $t0).TotalMilliseconds
            if ($sleep -gt 0) { Start-Sleep -Milliseconds ([int]$sleep) }
        }
        Emit-Snapshot -Final $true -No $snapNo
    }

    function Get-ResourceCategories {
        param($Settings)
        @{
            Names = @('Defender', 'Citrix', 'FSLogix', 'Office', 'Browser', 'Windows')
            Regex = @($Settings.CatDefender, $Settings.CatCitrix, $Settings.CatFslogix, $Settings.CatOffice, $Settings.CatBrowser, $Settings.CatWindows)
        }
    }

    function Build-ResourceResults {
        param([hashtable]$Data, [object[]]$Ticks, $Settings, [string[]]$CatNames, [hashtable]$Errors)
        $allCats = @($CatNames) + 'Sonstige'
        $warnAt = [double]$Settings.DefenderShareWarn
        $summary = New-Object System.Collections.Generic.List[object]
        $catRows = New-Object System.Collections.Generic.List[object]
        $procRows = New-Object System.Collections.Generic.List[object]
        $tickRows = New-Object System.Collections.Generic.List[object]
        $workers = New-Object System.Collections.Generic.List[string]
        $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $r1 = { param($v) [math]::Round([double]$v, 1) }
        $r2 = { param($v) [math]::Round([double]$v, 2) }

        $computers = @(@($Data.Keys) + @($Errors.Keys) | Sort-Object -Unique)
        foreach ($cn in $computers) {
            $label = Get-UniqueLabel -Label (Get-ShortName $cn) -Used $used
            $d = $Data[$cn]
            if (-not $d -or -not $d.Tot -or [double]$d.Tot.Elapsed100ns -le 0) {
                $msg = if ($Errors[$cn]) { $Errors[$cn] } else { 'Keine Messdaten (Messung zu kurz oder abgebrochen)' }
                $summary.Add([pscustomobject][ordered]@{ Worker = $label; Kerne = $null; Dauer_Min = $null; Messpunkte = $null; CPU_Gesamt_Prozent = $null
                    CPU_Defender_Prozent = $null; CPU_Defender_Max_Prozent = $null; CPU_Defender_P95_Prozent = $null; Defender_Kerne = $null
                    Defender_Anteil_CPU_Prozent = $null; Verhaeltnis_Defender_zu_Rest = $null; RAM_Defender_MB = $null; Defender_Anteil_RAM_Prozent = $null
                    IO_Defender_MBs = $null; Defender_Anteil_IO_Prozent = $null; Rang_Defender = $null; Top_Prozess = $null; Top_Prozess_CPU_Prozent = $null
                    Messaufwand_CPU_Prozent = $null; Anteil_Prozent = 0; Bewertung = 'Fehler'; Fehler = $msg })
                continue
            }
            $workers.Add($label)
            $t = $d.Tot
            $el = [double]$t.Elapsed100ns
            $cores = [int]$t.Cores
            $cap = $el * $cores
            $sec = $el / 1e7
            $totCpu = [double]$t.TotalCpu; $totIo = [double]$t.TotalIo; $totWs = [double]$t.TotalWsAvg

            foreach ($c in $d.Cats) {
                $catRows.Add([pscustomobject][ordered]@{
                    Worker           = $label
                    Kategorie        = $c.Kategorie
                    CPU_Prozent      = & $r2 ($c.Cpu / $cap * 100)
                    CPU_Anteil_Prozent = & $r1 $(if ($totCpu) { $c.Cpu / $totCpu * 100 } else { 0 })
                    Kerne            = & $r2 ($c.Cpu / $el)
                    RAM_MB           = & $r1 ($c.WsAvg / 1MB)
                    RAM_Anteil_Prozent = & $r1 $(if ($totWs) { $c.WsAvg / $totWs * 100 } else { 0 })
                    IO_MBs           = & $r2 ($c.Io / $sec / 1MB)
                    IO_Anteil_Prozent  = & $r1 $(if ($totIo) { $c.Io / $totIo * 100 } else { 0 })
                })
            }

            $sortedProcs = @($d.Procs | Sort-Object { [double]$_.Cpu } -Descending)
            $rank = 0; $defRank = $null
            foreach ($p in $sortedProcs) {
                $rank++
                if (-not $defRank -and $p.Kategorie -eq $CatNames[0]) { $defRank = $rank }
                $procRows.Add([pscustomobject][ordered]@{
                    Worker             = $label
                    Rang               = $rank
                    Prozess            = $p.Name
                    Kategorie          = $p.Kategorie
                    CPU_Prozent        = & $r2 ($p.Cpu / $cap * 100)
                    CPU_Anteil_Prozent = & $r1 $(if ($totCpu) { $p.Cpu / $totCpu * 100 } else { 0 })
                    CPU_Max_Prozent    = & $r1 $p.MaxCpuPct
                    Kerne              = & $r2 ($p.Cpu / $el)
                    RAM_MB             = & $r1 ($p.WsAvg / 1MB)
                    IO_MBs             = & $r2 ($p.Io / $sec / 1MB)
                    Instanzen_max      = $p.MaxInst
                })
            }

            $myTicks = @($Ticks | Where-Object { $_.PSComputerName -eq $cn } | Sort-Object Time)
            foreach ($tk in $myTicks) {
                $o = [ordered]@{ Worker = $label; Zeit = ('{0:HH:mm:ss}' -f $tk.Time); CPU_Gesamt_Prozent = & $r1 $tk.CpuTotalPct }
                for ($i = 0; $i -lt $allCats.Count; $i++) { $o["CPU_$(Get-SafeName $allCats[$i])_Prozent"] = & $r1 $tk."C$i" }
                $o['Defender_Anteil_Prozent'] = & $r1 $(if ([double]$tk.CpuTotalPct -gt 0) { [double]$tk.C0 / [double]$tk.CpuTotalPct * 100 } else { 0 })
                $tickRows.Add([pscustomobject]$o)
            }
            $defTicks = @($myTicks | ForEach-Object { [double]$_.C0 } | Sort-Object)
            $defMax = if ($defTicks.Count) { $defTicks[-1] } else { $null }
            $defP95 = if ($defTicks.Count) { $defTicks[[math]::Min($defTicks.Count - 1, [int][math]::Ceiling($defTicks.Count * 0.95) - 1)] } else { $null }

            $def = $d.Cats | Where-Object Kategorie -eq $CatNames[0] | Select-Object -First 1
            $defCpu = [double]$def.Cpu
            $restCpu = $totCpu - $defCpu
            $share = if ($totCpu) { $defCpu / $totCpu * 100 } else { 0 }
            $ratio = if ($defCpu -gt 0) { '1 : {0:N1}' -f ($restCpu / $defCpu) } else { '-' }
            $top = $sortedProcs | Select-Object -First 1
            $summary.Add([pscustomobject][ordered]@{
                Worker                      = $label
                Kerne                       = $cores
                Dauer_Min                   = & $r1 ($sec / 60)
                Messpunkte                  = $t.Samples
                CPU_Gesamt_Prozent          = & $r1 ($totCpu / $cap * 100)
                CPU_Defender_Prozent        = & $r2 ($defCpu / $cap * 100)
                CPU_Defender_Max_Prozent    = & $r1 $defMax
                CPU_Defender_P95_Prozent    = & $r1 $defP95
                Defender_Kerne              = & $r2 ($defCpu / $el)
                Defender_Anteil_CPU_Prozent = & $r1 $share
                Verhaeltnis_Defender_zu_Rest = $ratio
                RAM_Defender_MB             = & $r1 ($def.WsAvg / 1MB)
                Defender_Anteil_RAM_Prozent = & $r1 $(if ($totWs) { $def.WsAvg / $totWs * 100 } else { 0 })
                IO_Defender_MBs             = & $r2 ($def.Io / $sec / 1MB)
                Defender_Anteil_IO_Prozent  = & $r1 $(if ($totIo) { $def.Io / $totIo * 100 } else { 0 })
                Rang_Defender               = $defRank
                Top_Prozess                 = $top.Name
                Top_Prozess_CPU_Prozent     = & $r2 ($top.Cpu / $cap * 100)
                Messaufwand_CPU_Prozent     = & $r2 ([double]$t.OwnCpu / $cap * 100)
                Anteil_Prozent              = [math]::Min(100, (& $r1 $share))
                Bewertung                   = $(if ($share -ge $warnAt) { 'Warnung' } else { 'OK' })
                Fehler                      = $null
            })
        }

        # Vergleich: Kategorie x Worker (Anteil an der genutzten CPU)
        $pivot = foreach ($c in $allCats) {
            $o = [ordered]@{ Kategorie = $c }
            $vals = @()
            foreach ($w in $workers) {
                $v = ($catRows | Where-Object { $_.Worker -eq $w -and $_.Kategorie -eq $c } | Select-Object -First 1).CPU_Anteil_Prozent
                $o["$(Get-SafeName $w)_Prozent"] = $v
                if ($null -ne $v) { $vals += [double]$v }
            }
            $o['Mittel_Prozent'] = if ($vals.Count) { [math]::Round(($vals | Measure-Object -Average).Average, 1) } else { $null }
            $o['Max_Prozent'] = if ($vals.Count) { [math]::Round(($vals | Measure-Object -Maximum).Maximum, 1) } else { $null }
            $o['Markierung'] = $(if ($c -eq $CatNames[0]) { 'Defender' } else { '' })   # Defender-Zeile hervorheben
            [pscustomobject]$o
        }

        $res = @{
            Summary  = $summary.ToArray()
            CatPivot = @($pivot)
            Cats     = $catRows.ToArray()
            Procs    = $procRows.ToArray()
            Ticks    = $tickRows.ToArray()
            Workers  = $workers.ToArray()
            CatNames = $allCats
            Created  = Get-Date
        }
        $res.Hints = Get-ResourceHints -Res $res -WarnAt $warnAt
        return $res
    }

    function Get-ResourceHints {
        param($Res, [double]$WarnAt)
        $h = New-Object System.Collections.Generic.List[string]
        $ok = @($Res.Summary | Where-Object { -not $_.Fehler })
        foreach ($e in @($Res.Summary | Where-Object Fehler)) { $h.Add("✖ $($e.Worker): $($e.Fehler)") }
        if ($ok.Count) {
            $avgShare = ($ok | Measure-Object Defender_Anteil_CPU_Prozent -Average).Average
            $avgMach  = ($ok | Measure-Object CPU_Defender_Prozent -Average).Average
            $avgTot   = ($ok | Measure-Object CPU_Gesamt_Prozent -Average).Average
            $avgCores = ($ok | Measure-Object Defender_Kerne -Average).Average
            $avgRam   = ($ok | Measure-Object RAM_Defender_MB -Average).Average
            $h.Add(('■ Ueber {0} Worker: Defender nutzt im Schnitt {1:N1} % der genutzten CPU (= {2:N2} % der Gesamtkapazitaet, {3:N2} Kerne) bei {4:N1} % CPU-Gesamtlast. Verhaeltnis Defender zu Rest ca. 1 : {5:N1}. RAM Defender im Schnitt {6:N0} MB.' -f `
                $ok.Count, $avgShare, $avgMach, $avgCores, $avgTot, $(if ($avgShare -gt 0) { (100 - $avgShare) / $avgShare } else { 0 }), $avgRam))
            foreach ($r in ($ok | Where-Object { $_.Defender_Anteil_CPU_Prozent -ge $WarnAt } | Sort-Object Defender_Anteil_CPU_Prozent -Descending)) {
                $h.Add(('⚠ {0}: Defender-Anteil {1:N1} % liegt ueber der Warnschwelle von {2} % (Spitze {3:N1} % der Gesamtkapazitaet).' -f $r.Worker, $r.Defender_Anteil_CPU_Prozent, $WarnAt, $r.CPU_Defender_Max_Prozent))
            }
            $topDef = @($ok | Where-Object { $_.Rang_Defender -eq 1 })
            if ($topDef.Count) { $h.Add("⚠ Ein Defender-Prozess ist der groesste CPU-Verbraucher auf: $(($topDef | ForEach-Object Worker) -join ', ').") }
            $peaks = @($ok | Where-Object { [double]$_.CPU_Defender_Max_Prozent -ge 50 })
            if ($peaks.Count) { $h.Add("ℹ Defender-Spitzen ueber 50 % der Gesamtkapazitaet in einem Intervall: $(($peaks | ForEach-Object Worker) -join ', '). Zeitpunkte im Tab 'Verlauf'.") }
            $dp = @($Res.Procs | Where-Object Kategorie -eq 'Defender' | Group-Object Prozess | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Cpu = ($_.Group | Measure-Object CPU_Prozent -Average).Average }
            } | Sort-Object Cpu -Descending | Select-Object -First 3)
            if ($dp.Count) { $h.Add('ℹ Groesste Defender-Prozesse (Ø CPU der Gesamtkapazitaet): ' + (($dp | ForEach-Object { '{0} {1:N2} %' -f $_.Name, $_.Cpu }) -join ', ')) }
        }
        $h.Add('')
        $h.Add('Hinweise zur Messung:')
        $h.Add('• "Anteil" = Anteil an der tatsaechlich genutzten CPU (ohne Leerlauf). "CPU %" = Anteil an der Gesamtkapazitaet aller Kerne.')
        $h.Add('• Ein Teil der Scanarbeit des Defender-Filtertreibers wird im Kontext des aufrufenden Prozesses bzw. des Systems verbucht. Die Werte fuer Defender sind daher eine Untergrenze.')
        $h.Add('• Prozesse, die zwischen zwei Messpunkten starten und enden, fehlen. Die Messung selbst (wsmprovhost) ist herausgerechnet, siehe "Messaufwand".')
        return ($h -join [Environment]::NewLine)
    }

    function Invoke-ResourceMeasurement {
        param($A)
        $S = $A.Settings
        $cats = Get-ResourceCategories $S
        $minutes = [double]$S.ResMinutes
        Write-Log ("Ressourcenmessung: {0} Server, {1} Minuten, Intervall {2} s" -f $A.Servers.Count, $minutes, $S.ResIntervalSec)
        foreach ($srv in $A.Servers) { Set-ServerStatus $srv @{ Status = 'Verbinde...'; Meldung = '' } }
        $sessions = @(Open-Sessions -Servers $A.Servers -Settings $S -Credential $A.Credential)
        if (-not $sessions) { Write-Log 'Keine Verbindung zu einem Server moeglich.' 'ERROR'; return }

        $data = @{}; $buf = @{}; $errors = @{}
        $ticks = New-Object System.Collections.Generic.List[object]
        $handle = {
            param($items)
            foreach ($o in @($items)) {
                if ($null -eq $o -or -not $o.PSObject.Properties['Kind']) { continue }
                $cn = $o.PSComputerName
                switch ($o.Kind) {
                    'Tick' { $ticks.Add($o) }
                    'SnapProc' {
                        if (-not $buf.ContainsKey("$cn|$($o.Snap)")) { $buf["$cn|$($o.Snap)"] = @{ Procs = New-Object System.Collections.Generic.List[object]; Cats = New-Object System.Collections.Generic.List[object] } }
                        $buf["$cn|$($o.Snap)"].Procs.Add($o)
                    }
                    'SnapCat' {
                        if (-not $buf.ContainsKey("$cn|$($o.Snap)")) { $buf["$cn|$($o.Snap)"] = @{ Procs = New-Object System.Collections.Generic.List[object]; Cats = New-Object System.Collections.Generic.List[object] } }
                        $buf["$cn|$($o.Snap)"].Cats.Add($o)
                    }
                    'SnapTot' {
                        $b = $buf["$cn|$($o.Snap)"]
                        if ($b) {
                            $data[$cn] = @{ Tot = $o; Procs = $b.Procs.ToArray(); Cats = $b.Cats.ToArray() }
                            $buf.Remove("$cn|$($o.Snap)")
                        }
                        Set-ServerStatus $cn @{ Status = $(if ($o.Final) { 'Messung fertig' } else { 'Messung laeuft' }); Meldung = ('{0} Messpunkte, {1} Prozesse' -f $o.Samples, $o.ProcessCount) }
                    }
                }
            }
        }

        try {
            foreach ($sx in $sessions) { Set-ServerStatus $sx.ComputerName @{ Status = 'Messung laeuft' } }
            $snapSec = [int][math]::Max(15, [math]::Min(60, $minutes * 60 / 6))
            $job = Invoke-Command -Session $sessions -ScriptBlock ${function:Remote-ResourceSample} -AsJob -ThrottleLimit ([int]$S.ThrottleLimit) `
                -ArgumentList $minutes, ([int]$S.ResIntervalSec), $cats.Names, $cats.Regex, ([int]$S.ResTopN), $snapSec
            $start = Get-Date
            while ($job.State -in 'NotStarted', 'Running') {
                & $handle (Receive-Job $job -ErrorAction SilentlyContinue)
                $elapsed = ((Get-Date) - $start).TotalSeconds
                $sync.Progress = [math]::Min(100, [math]::Round($elapsed / ($minutes * 60) * 100, 0))
                $left = [TimeSpan]::FromSeconds([math]::Max(0, $minutes * 60 - $elapsed))
                $sync.ProgressText = ('Messung laeuft – noch {0:mm\:ss}' -f $left)
                if ($sync.Cancel) {
                    Stop-Job $job
                    foreach ($sx in $sessions) { Set-ServerStatus $sx.ComputerName @{ Status = 'Abgebrochen' } }
                    Write-Log 'Ressourcenmessung abgebrochen, keine Auswertung.' 'WARN'
                    return
                }
                if ($sync.StopNow) {
                    Write-Log 'Ressourcenmessung wird vorzeitig beendet (letzter Zwischenstand wird ausgewertet).'
                    Stop-Job $job
                    break
                }
                Start-Sleep -Milliseconds 1000
            }
            & $handle (Receive-Job $job -ErrorAction SilentlyContinue)
            foreach ($cj in $job.ChildJobs) {
                if ($cj.State -eq 'Failed') {
                    $msg = "$($cj.JobStateInfo.Reason.Message)"
                    $cn = $cj.Location
                    $errors[$cn] = $msg
                    Set-ServerStatus $cn @{ Status = 'Fehler'; Meldung = $msg }
                    Write-Log "$cn : $msg" 'ERROR'
                }
            }
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            foreach ($sx in $sessions) { if (-not $data.ContainsKey($sx.ComputerName) -and -not $errors.ContainsKey($sx.ComputerName)) { $errors[$sx.ComputerName] = 'Keine Messdaten (Messung zu kurz oder abgebrochen)' } }

            $sync.ProgressText = 'Werte Messung aus...'
            $res = Build-ResourceResults -Data $data -Ticks $ticks.ToArray() -Settings $S -CatNames $cats.Names -Errors $errors
            $sync.ResResults = $res
            $sync.ResReady = $true
            Write-Log ("Ressourcenmessung ausgewertet: {0} Worker" -f @($res.Workers).Count)
        }
        finally {
            Remove-PSSession $sessions -ErrorAction SilentlyContinue
            $sync.ProgressText = ''
        }
    }

    function Export-Table {
        # Exportiert benannte Tabellen als CSV (+ optional Excel); Spalte "Raw" wird separat als JSON/Text abgelegt
        param([System.Collections.IDictionary]$Sets, [string]$Folder, $Settings, [string]$XlsxName)
        $null = New-Item -ItemType Directory -Path $Folder -Force
        $written = New-Object System.Collections.Generic.List[string]
        foreach ($name in $Sets.Keys) {
            $data = @($Sets[$name])
            if ($data.Count -eq 0) { continue }
            $hasRaw = $data[0].PSObject.Properties['Raw']
            $flat = if ($hasRaw) { $data | Select-Object * -ExcludeProperty Raw } else { $data }
            $file = Join-Path $Folder "$name.csv"
            $flat | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 -Delimiter ([char]$Settings.CsvDelimiter)
            $written.Add($file)
            if ($hasRaw) {
                $rawFile = Join-Path $Folder "$name`_Details.txt"
                ($data | ForEach-Object { "##### $($_.Richtlinie) / $($_.Regel)`n$($_.Raw)`n" }) -join "`n" | Set-Content -Path $rawFile -Encoding UTF8
                $written.Add($rawFile)
            }
        }
        if ($Settings.ExportExcel) {
            if (Get-Module -ListAvailable -Name ImportExcel) {
                Import-Module ImportExcel -ErrorAction Stop
                $xlsx = Join-Path $Folder $XlsxName
                if (Test-Path $xlsx) { Remove-Item $xlsx -Force }
                foreach ($name in $Sets.Keys) {
                    $data = @($Sets[$name])
                    if ($data.Count -eq 0) { continue }
                    if ($data[0].PSObject.Properties['Raw']) { $data = $data | Select-Object * -ExcludeProperty Raw }
                    $ws = $name.Substring(0, [math]::Min(31, $name.Length))
                    $data | Export-Excel -Path $xlsx -WorksheetName $ws -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -TableStyle Medium2 -TableName ($ws -replace '\W', '')
                }
                $written.Add($xlsx)
            }
            else { Write-Log 'Excel-Export uebersprungen: Modul ImportExcel fehlt.' 'WARN' }
        }
        return $written
    }
}
. $CoreBlock
#endregion

#region XAML
$XamlText = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Defender Performance Analyzer – Citrix Worker" Height="840" Width="1320" MinHeight="650" MinWidth="1050"
        WindowStartupLocation="CenterScreen" FontFamily="Segoe UI" FontSize="12" Background="#F3F4F6">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="12,5"/>
      <Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="MinWidth" Value="90"/>
    </Style>
    <Style TargetType="GroupBox">
      <Setter Property="Margin" Value="0,0,0,10"/>
      <Setter Property="Padding" Value="8"/>
      <Setter Property="Background" Value="White"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="3"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="0,4,0,4"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="True"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="CanUserAddRows" Value="False"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#E5E7EB"/>
      <Setter Property="AlternatingRowBackground" Value="#F7F9FC"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#D0D5DD"/>
      <Setter Property="SelectionMode" Value="Extended"/>
      <Setter Property="ClipboardCopyMode" Value="IncludeHeader"/>
    </Style>
  </Window.Resources>

  <DockPanel>
    <Border DockPanel.Dock="Top" Background="#1F3864" Padding="16,10">
      <StackPanel>
        <TextBlock Text="Defender Performance Analyzer" Foreground="White" FontSize="18" FontWeight="SemiBold"/>
        <TextBlock Text="Aufnahme und Vergleich der Defender-Scanlast auf Citrix-Workern" Foreground="#C9D3E6"/>
      </StackPanel>
    </Border>

    <Border DockPanel.Dock="Bottom" Background="#E5E7EB" Padding="10,5">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="240"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="lblStatus" Text="Bereit" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        <TextBlock x:Name="lblProgress" Grid.Column="1" Margin="10,0" VerticalAlignment="Center" FontWeight="SemiBold"/>
        <ProgressBar x:Name="pbProgress" Grid.Column="2" Height="14" Minimum="0" Maximum="100"/>
      </Grid>
    </Border>

    <TabControl x:Name="tabMain" Margin="10">

      <TabItem Header="  Server &amp; Aufnahme  ">
        <Grid Margin="8">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="300"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <GroupBox Header="Server (einer pro Zeile, # = Kommentar)" Grid.Column="0" Margin="0,0,10,10">
            <DockPanel>
              <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
                <Button x:Name="btnLoadServers" Content="Aus Datei..."/>
                <Button x:Name="btnTest" Content="Verbindung testen" Margin="0"/>
              </StackPanel>
              <TextBox x:Name="txtServers" AcceptsReturn="True" TextWrapping="NoWrap" VerticalContentAlignment="Top"
                       VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" FontFamily="Consolas"/>
            </DockPanel>
          </GroupBox>

          <GroupBox Header="Status pro Server" Grid.Column="1">
            <DataGrid x:Name="gridServers"/>
          </GroupBox>

          <GroupBox Header="Aufnahme / Auswertung" Grid.Row="1" Grid.ColumnSpan="2" Margin="0">
            <StackPanel>
              <WrapPanel>
                <TextBlock Text="Dauer (Minuten):" VerticalAlignment="Center" Margin="0,0,6,0"/>
                <TextBox x:Name="txtRecordMinutes" Width="60" Margin="0,0,16,0"/>
                <Button x:Name="btnStart" Content="▶  Aufnahme starten" FontWeight="SemiBold"/>
                <Button x:Name="btnStopNow" Content="■  Jetzt beenden &amp; auswerten"/>
                <Button x:Name="btnCancel" Content="✖  Abbrechen"/>
                <Border Width="1" Height="24" Margin="8,0,16,0" Background="#D0D5DD"/>
                <Button x:Name="btnAnalyzeFolder" Content="ETL-Ordner auswerten..."/>
                <Button x:Name="btnAnalyzeFiles" Content="ETL-Dateien auswerten..."/>
              </WrapPanel>
              <TextBlock Margin="0,8,0,0" Foreground="#555" TextWrapping="Wrap"
                         Text="Tipp: Aufnahme waehrend der Logon-Spitze (z.B. 07:30–08:30). Die ETL-Dateien werden automatisch eingesammelt, ausgewertet und unter 'Ergebnisse' angezeigt."/>
            </StackPanel>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem x:Name="tabResults" Header="  Ergebnisse  ">
        <DockPanel Margin="8">
          <DockPanel DockPanel.Dock="Top" Margin="0,0,0,8">
            <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
              <Button x:Name="btnExport" Content="Exportieren (CSV/Excel)"/>
              <Button x:Name="btnOpenFolder" Content="Ausgabeordner oeffnen"/>
            </StackPanel>
            <TextBlock x:Name="lblResultInfo" VerticalAlignment="Center" Foreground="#555" Margin="8,0" TextTrimming="CharacterEllipsis"/>
          </DockPanel>
          <TabControl>
            <TabItem Header="Zusammenfassung">
              <Grid Margin="4">
                <Grid.RowDefinitions>
                  <RowDefinition Height="*"/>
                  <RowDefinition Height="180"/>
                </Grid.RowDefinitions>
                <DataGrid x:Name="gridSummary">
                  <DataGrid.Columns>
                    <DataGridTemplateColumn Header="Scanlast (relativ)" Width="150" CanUserSort="True" SortMemberPath="Anteil_Prozent">
                      <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                          <ProgressBar Value="{Binding Anteil_Prozent, Mode=OneWay}" Maximum="100" Height="12" Margin="4,0" Foreground="#2E75B6"/>
                        </DataTemplate>
                      </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                  </DataGrid.Columns>
                </DataGrid>
                <GroupBox Header="Hinweise" Grid.Row="1" Margin="0,8,0,0">
                  <TextBox x:Name="txtHints" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                           VerticalContentAlignment="Top" BorderThickness="0" FontSize="13"/>
                </GroupBox>
              </Grid>
            </TabItem>
            <TabItem Header="Vergleich Pfade">
              <DataGrid x:Name="gridPaths" Margin="4"/>
            </TabItem>
            <TabItem Header="Vergleich Prozesse">
              <DataGrid x:Name="gridProcs" Margin="4"/>
            </TabItem>
            <TabItem Header="Vergleich Dateiendungen">
              <DataGrid x:Name="gridExts" Margin="4"/>
            </TabItem>
            <TabItem Header="Details">
              <DockPanel Margin="4">
                <WrapPanel DockPanel.Dock="Top" Margin="0,0,0,8">
                  <TextBlock Text="Datensatz:" VerticalAlignment="Center" Margin="0,0,6,0"/>
                  <ComboBox x:Name="cmbDetailSet" Width="150" Margin="0,0,16,0" SelectedIndex="4">
                    <ComboBoxItem Content="Pfade" Tag="AllPaths"/>
                    <ComboBoxItem Content="Prozesse" Tag="AllProcs"/>
                    <ComboBoxItem Content="Dateiendungen" Tag="AllExts"/>
                    <ComboBoxItem Content="Dateien" Tag="AllFiles"/>
                    <ComboBoxItem Content="Einzelscans" Tag="AllScans"/>
                  </ComboBox>
                  <TextBlock Text="Worker:" VerticalAlignment="Center" Margin="0,0,6,0"/>
                  <ComboBox x:Name="cmbDetailWorker" Width="160" Margin="0,0,16,0"/>
                  <TextBlock Text="Filter (Text):" VerticalAlignment="Center" Margin="0,0,6,0"/>
                  <TextBox x:Name="txtDetailFilter" Width="280" Margin="0,0,16,0"/>
                  <TextBlock x:Name="lblDetailCount" VerticalAlignment="Center" Foreground="#555"/>
                </WrapPanel>
                <DataGrid x:Name="gridDetails"/>
              </DockPanel>
            </TabItem>
          </TabControl>
        </DockPanel>
      </TabItem>

      <TabItem x:Name="tabRes" Header="  Ressourcen: Defender vs. Rest  ">
        <DockPanel Margin="8">
          <StackPanel DockPanel.Dock="Top" Margin="0,0,0,8">
            <WrapPanel>
              <TextBlock Text="Dauer (Minuten):" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtResMinutes" Width="50" Margin="0,0,12,0"/>
              <TextBlock Text="Intervall (Sekunden):" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtResInterval" Width="50" Margin="0,0,16,0"/>
              <Button x:Name="btnResStart" Content="▶  Messung starten (Serverliste)" FontWeight="SemiBold"/>
              <Button x:Name="btnResStop" Content="■  Jetzt beenden &amp; auswerten"/>
              <Button x:Name="btnResCancel" Content="✖  Abbrechen"/>
              <Button x:Name="btnResExport" Content="Exportieren..."/>
            </WrapPanel>
            <TextBlock Margin="0,6,0,0" Foreground="#555" TextWrapping="Wrap"
                       Text="Misst periodisch CPU, privaten Arbeitsspeicher und Disk-/Netz-I/O aller Prozesse (sprachunabhaengig ueber Leistungsindikatoren) und vergleicht Defender (MsMpEng, MsSense, Sense*, NisSrv, ...) mit allen anderen Prozessen. Am aussagekraeftigsten waehrend normaler Benutzerlast oder der Logon-Spitze."/>
            <WrapPanel Margin="0,8,0,0">
              <TextBlock Text="Worker:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <ComboBox x:Name="cmbResWorker" Width="160" Margin="0,0,16,0"/>
              <TextBlock Text="Filter (Text):" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtResFilter" Width="220" Margin="0,0,16,0"/>
              <CheckBox x:Name="chkResDefOnly" Content="Nur Defender-Prozesse" Margin="0,0,16,0"/>
              <TextBlock x:Name="lblResInfo" VerticalAlignment="Center" Foreground="#555"/>
            </WrapPanel>
          </StackPanel>
          <TabControl>
            <TabItem Header="Uebersicht pro Worker">
              <Grid Margin="4">
                <Grid.RowDefinitions>
                  <RowDefinition Height="*"/>
                  <RowDefinition Height="190"/>
                </Grid.RowDefinitions>
                <DataGrid x:Name="gridResSummary" AlternatingRowBackground="{x:Null}">
                  <DataGrid.RowStyle>
                    <Style TargetType="DataGridRow">
                      <Style.Triggers>
                        <DataTrigger Binding="{Binding Bewertung}" Value="Warnung"><Setter Property="Background" Value="#FFF1DC"/></DataTrigger>
                        <DataTrigger Binding="{Binding Bewertung}" Value="Fehler"><Setter Property="Background" Value="#FDE2E2"/></DataTrigger>
                      </Style.Triggers>
                    </Style>
                  </DataGrid.RowStyle>
                  <DataGrid.Columns>
                    <DataGridTemplateColumn Header="Defender-Anteil an genutzter CPU" Width="190" CanUserSort="True" SortMemberPath="Defender_Anteil_CPU_Prozent">
                      <DataGridTemplateColumn.CellTemplate>
                        <DataTemplate>
                          <Grid Margin="4,0">
                            <ProgressBar Value="{Binding Anteil_Prozent, Mode=OneWay}" Maximum="100" Height="14" Foreground="#C0504D"/>
                            <TextBlock Text="{Binding Defender_Anteil_CPU_Prozent, StringFormat={}{0:N1} %}" HorizontalAlignment="Center" FontSize="10" VerticalAlignment="Center"/>
                          </Grid>
                        </DataTemplate>
                      </DataGridTemplateColumn.CellTemplate>
                    </DataGridTemplateColumn>
                  </DataGrid.Columns>
                </DataGrid>
                <GroupBox Header="Ergebnis und Hinweise" Grid.Row="1" Margin="0,8,0,0">
                  <TextBox x:Name="txtResHints" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                           VerticalContentAlignment="Top" BorderThickness="0" FontSize="13"/>
                </GroupBox>
              </Grid>
            </TabItem>
            <TabItem Header="Vergleich Kategorien">
              <DataGrid x:Name="gridResPivot" Margin="4" AlternatingRowBackground="{x:Null}">
                <DataGrid.RowStyle>
                  <Style TargetType="DataGridRow">
                    <Style.Triggers>
                      <DataTrigger Binding="{Binding Markierung}" Value="Defender"><Setter Property="Background" Value="#FBE3E2"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
                    </Style.Triggers>
                  </Style>
                </DataGrid.RowStyle>
              </DataGrid>
            </TabItem>
            <TabItem Header="Kategorien pro Worker">
              <DataGrid x:Name="gridResCats" Margin="4"/>
            </TabItem>
            <TabItem Header="Top-Prozesse">
              <DataGrid x:Name="gridResProcs" Margin="4" AlternatingRowBackground="{x:Null}">
                <DataGrid.RowStyle>
                  <Style TargetType="DataGridRow">
                    <Style.Triggers>
                      <DataTrigger Binding="{Binding Kategorie}" Value="Defender"><Setter Property="Background" Value="#FBE3E2"/></DataTrigger>
                    </Style.Triggers>
                  </Style>
                </DataGrid.RowStyle>
              </DataGrid>
            </TabItem>
            <TabItem Header="Verlauf">
              <DataGrid x:Name="gridResTicks" Margin="4"/>
            </TabItem>
          </TabControl>
        </DockPanel>
      </TabItem>

      <TabItem x:Name="tabFeatures" Header="  Defender-Features  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="150"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,8">
            <WrapPanel>
              <Button x:Name="btnFeatures" Content="Features einlesen (Serverliste)" FontWeight="SemiBold"/>
              <Button x:Name="btnFeatExport" Content="Exportieren..."/>
              <TextBlock Text="Ansicht:" VerticalAlignment="Center" Margin="8,0,6,0"/>
              <ComboBox x:Name="cmbFeatView" Width="200" SelectedIndex="0" Margin="0,0,16,0">
                <ComboBoxItem Content="Uebersicht pro Server"/>
                <ComboBoxItem Content="Matrix (Vergleich)"/>
                <ComboBoxItem Content="Liste (alle Werte)"/>
              </ComboBox>
              <CheckBox x:Name="chkFeatDiffOnly" Content="Nur Abweichungen" Margin="0,0,16,0"/>
              <CheckBox x:Name="chkFeatWarnOnly" Content="Nur Warnungen/Fehler" Margin="0,0,16,0"/>
              <TextBlock Text="Filter:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtFeatFilter" Width="220" Margin="0,0,16,0"/>
              <TextBlock x:Name="lblFeatCount" VerticalAlignment="Center" Foreground="#555"/>
            </WrapPanel>
            <TextBlock Margin="0,6,0,0" Foreground="#555" TextWrapping="Wrap"
                       Text="Liest per Remoting Get-MpComputerStatus, Get-MpPreference, ASR-Regeln, MDE-Onboarding, GPO/MDM-Herkunft, Firewall und den lokalen Endpoint-DLP-Status. Farben: orange = Warnung, rot = Fehler, blau = Abweichung zwischen Servern."/>
          </StackPanel>
          <DataGrid x:Name="gridFeatures" Grid.Row="1" AlternatingRowBackground="{x:Null}">
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Style.Triggers>
                  <DataTrigger Binding="{Binding Bewertung}" Value="Warnung"><Setter Property="Background" Value="#FFF1DC"/></DataTrigger>
                  <DataTrigger Binding="{Binding Bewertung}" Value="Fehler"><Setter Property="Background" Value="#FDE2E2"/></DataTrigger>
                  <DataTrigger Binding="{Binding Bewertung}" Value="Abweichung"><Setter Property="Background" Value="#E3EEFF"/></DataTrigger>
                </Style.Triggers>
              </Style>
            </DataGrid.RowStyle>
          </DataGrid>
          <GroupBox Header="Details zur Auswahl" Grid.Row="2" Margin="0,8,0,0">
            <TextBox x:Name="txtFeatDetail" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     VerticalContentAlignment="Top" BorderThickness="0" FontFamily="Consolas"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem x:Name="tabDlp" Header="  DLP (Purview)  ">
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="220"/>
          </Grid.RowDefinitions>
          <StackPanel Margin="0,0,0,8">
            <WrapPanel>
              <TextBlock Text="Admin-UPN:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtUpn" Width="240" Margin="0,0,12,0"/>
              <CheckBox x:Name="chkEndpointOnly" Content="Nur Endpoint-DLP (Geraete)" Margin="0,0,12,0"/>
              <CheckBox x:Name="chkDisableWam" Content="WAM deaktivieren (bei Anmeldeproblemen)" Margin="0,0,12,0"/>
              <Button x:Name="btnDlpLoad" Content="Verbinden &amp; DLP-Regeln einlesen" FontWeight="SemiBold"/>
              <Button x:Name="btnDlpExport" Content="Exportieren..."/>
            </WrapPanel>
            <WrapPanel Margin="0,8,0,0">
              <TextBlock Text="Filter:" VerticalAlignment="Center" Margin="0,0,6,0"/>
              <TextBox x:Name="txtDlpFilter" Width="260" Margin="0,0,16,0"/>
              <CheckBox x:Name="chkDlpActiveOnly" Content="Nur aktive Regeln" Margin="0,0,16,0"/>
              <TextBlock x:Name="lblDlpCount" VerticalAlignment="Center" Foreground="#555"/>
            </WrapPanel>
            <TextBlock Margin="0,6,0,0" Foreground="#555" TextWrapping="Wrap"
                       Text="Benoetigt das Modul ExchangeOnlineManagement und mind. die Rolle 'View-Only DLP Compliance Management'. Grau = Richtlinie oder Regel aus. Den lokalen DLP-Status pro Worker zeigt der Tab 'Defender-Features' (Bereich 'Endpoint DLP (Geraet)')."/>
          </StackPanel>
          <DataGrid x:Name="gridDlp" Grid.Row="1" AlternatingRowBackground="{x:Null}">
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Style.Triggers>
                  <DataTrigger Binding="{Binding Bewertung}" Value="Aus"><Setter Property="Foreground" Value="#8A8A8A"/></DataTrigger>
                  <DataTrigger Binding="{Binding Bewertung}" Value="Info"><Setter Property="Background" Value="#F2F6FC"/></DataTrigger>
                </Style.Triggers>
              </Style>
            </DataGrid.RowStyle>
          </DataGrid>
          <GroupBox Header="Details zur Auswahl (Rohdaten Richtlinie und Regel)" Grid.Row="2" Margin="0,8,0,0">
            <TextBox x:Name="txtDlpDetail" IsReadOnly="True" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto"
                     HorizontalScrollBarVisibility="Auto" VerticalContentAlignment="Top" BorderThickness="0" FontFamily="Consolas"/>
          </GroupBox>
        </Grid>
      </TabItem>

      <TabItem x:Name="tabSettings" Header="  Einstellungen  ">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
          <StackPanel Margin="8" MaxWidth="950" HorizontalAlignment="Left">

            <GroupBox Header="Aufnahme auf den Workern">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="280"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Text="Ablageordner auf dem Worker:" VerticalAlignment="Center"/>
                <TextBox x:Name="txtRemoteFolder" Grid.Column="1" Margin="0,3"/>
                <TextBlock Text="WPR-Instanzname:" Grid.Row="1" VerticalAlignment="Center"/>
                <TextBox x:Name="txtInstance" Grid.Row="1" Grid.Column="1" Margin="0,3" Width="250" HorizontalAlignment="Left"/>
                <CheckBox x:Name="chkCancelExisting" Grid.Row="2" Grid.ColumnSpan="2" Content="Laufende WPR-Aufnahme vor dem Start abbrechen"/>
                <CheckBox x:Name="chkFallbackProfile" Grid.Row="3" Grid.ColumnSpan="2" Content="Eigenes WPR-Profil verwenden, falls das Defender-Profil nicht gefunden wird (experimentell)"/>
                <CheckBox x:Name="chkDeleteRemote" Grid.Row="4" Grid.ColumnSpan="2" Content="ETL-Datei nach dem Einsammeln auf dem Worker loeschen"/>
              </Grid>
            </GroupBox>

            <GroupBox Header="Verbindung">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="280"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <CheckBox x:Name="chkUseCredential" Grid.ColumnSpan="2" Content="Andere Anmeldedaten verwenden (Abfrage beim Start)"/>
                <TextBlock Text="Max. parallele Verbindungen:" Grid.Row="1" VerticalAlignment="Center"/>
                <TextBox x:Name="txtThrottle" Grid.Row="1" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
              </Grid>
            </GroupBox>

            <GroupBox Header="Auswertung">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="280"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Text="Auswertung ausfuehren:" VerticalAlignment="Center"/>
                <ComboBox x:Name="cmbAnalyzeLocation" Grid.Column="1" Width="250" HorizontalAlignment="Left" Margin="0,3">
                  <ComboBoxItem Content="Lokal (auf diesem PC)" Tag="Lokal"/>
                  <ComboBoxItem Content="Auf dem Worker (remote)" Tag="Remote"/>
                </ComboBox>
                <TextBlock Text="Top-Eintraege (Pfade, Prozesse, Dateien):" Grid.Row="1" VerticalAlignment="Center"/>
                <TextBox x:Name="txtTop" Grid.Row="1" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Text="Pfadtiefe (C:\ = 1, C:\Users\Foo = 3):" Grid.Row="2" VerticalAlignment="Center"/>
                <TextBox x:Name="txtDepth" Grid.Row="2" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Text="Einzelscans pro Worker:" Grid.Row="3" VerticalAlignment="Center"/>
                <TextBox x:Name="txtTopScans" Grid.Row="3" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Text="Zeilen in Vergleichstabellen:" Grid.Row="4" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCompareTop" Grid.Row="4" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Text="Einheit numerischer Dauern (Raw-Ausgabe):" Grid.Row="5" VerticalAlignment="Center"/>
                <ComboBox x:Name="cmbDurationUnit" Grid.Row="5" Grid.Column="1" Width="150" HorizontalAlignment="Left" Margin="0,3">
                  <ComboBoxItem Content="Ticks (100 ns)" Tag="Ticks"/>
                  <ComboBoxItem Content="Millisekunden" Tag="Milliseconds"/>
                  <ComboBoxItem Content="Sekunden" Tag="Seconds"/>
                </ComboBox>
                <TextBlock Text="Worker-Name aus Dateiname (Regex):" Grid.Row="6" VerticalAlignment="Center"/>
                <TextBox x:Name="txtWorkerRegex" Grid.Row="6" Grid.Column="1" Width="250" HorizontalAlignment="Left" Margin="0,3" FontFamily="Consolas"/>
              </Grid>
            </GroupBox>

            <GroupBox Header="Ressourcenmessung (Defender vs. Rest)">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="280"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Text="Top-Prozesse pro Worker:" VerticalAlignment="Center"/>
                <TextBox x:Name="txtResTopN" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Text="Warnschwelle Defender-Anteil CPU (%):" Grid.Row="1" VerticalAlignment="Center"/>
                <TextBox x:Name="txtResWarn" Grid.Row="1" Grid.Column="1" Width="80" HorizontalAlignment="Left" Margin="0,3"/>
                <TextBlock Grid.Row="2" Grid.ColumnSpan="2" Margin="0,8,0,2" Foreground="#555" TextWrapping="Wrap"
                           Text="Zuordnung der Prozesse zu Kategorien (Regex auf den Prozessnamen ohne .exe, Gross-/Kleinschreibung egal; Reihenfolge = Prioritaet, nicht zugeordnete Prozesse = Sonstige):"/>
                <TextBlock Text="Defender:" Grid.Row="3" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatDefender" Grid.Row="3" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
                <TextBlock Text="Citrix:" Grid.Row="4" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatCitrix" Grid.Row="4" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
                <TextBlock Text="FSLogix:" Grid.Row="5" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatFslogix" Grid.Row="5" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
                <TextBlock Text="Office / M365:" Grid.Row="6" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatOffice" Grid.Row="6" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
                <TextBlock Text="Browser:" Grid.Row="7" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatBrowser" Grid.Row="7" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
                <TextBlock Text="Windows / System:" Grid.Row="8" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCatWindows" Grid.Row="8" Grid.Column="1" Margin="0,3" FontFamily="Consolas"/>
              </Grid>
            </GroupBox>

            <GroupBox Header="Ablage &amp; Export">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="280"/>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Text="Sammelordner (lokal oder Share):" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCollectFolder" Grid.Column="1" Margin="0,3,8,3"/>
                <Button x:Name="btnBrowseCollect" Grid.Column="2" Content="..." MinWidth="40" Margin="0"/>
                <CheckBox x:Name="chkExportCsv" Grid.Row="1" Grid.ColumnSpan="3" Content="Nach der Auswertung automatisch als CSV exportieren"/>
                <CheckBox x:Name="chkExportExcel" Grid.Row="2" Grid.ColumnSpan="3" Content="Zusaetzlich Excel-Datei erstellen (benoetigt Modul ImportExcel)"/>
                <TextBlock Text="CSV-Trennzeichen:" Grid.Row="3" VerticalAlignment="Center"/>
                <TextBox x:Name="txtCsvDelimiter" Grid.Row="3" Grid.Column="1" Width="40" HorizontalAlignment="Left" Margin="0,3" MaxLength="1"/>
              </Grid>
            </GroupBox>

            <StackPanel Orientation="Horizontal">
              <Button x:Name="btnSaveSettings" Content="Einstellungen speichern"/>
              <Button x:Name="btnResetSettings" Content="Standardwerte"/>
              <TextBlock x:Name="lblSettingsPath" VerticalAlignment="Center" Foreground="#777" Margin="8,0"/>
            </StackPanel>
          </StackPanel>
        </ScrollViewer>
      </TabItem>

      <TabItem Header="  Protokoll  ">
        <TextBox x:Name="txtLog" Margin="8" IsReadOnly="True" FontFamily="Consolas" TextWrapping="NoWrap" VerticalContentAlignment="Top"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
      </TabItem>
    </TabControl>
  </DockPanel>
</Window>
'@
#endregion

#region GUI laden
[xml]$xaml = $XamlText
$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
foreach ($node in $xaml.SelectNodes('//*')) {
    $nameAttr = $node.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1
    if ($nameAttr) { $ui[$nameAttr.Value] = $window.FindName($nameAttr.Value) }
}
#endregion

#region Einstellungen
$SettingsDir  = Join-Path $env:APPDATA 'DefenderPerfGui'
$SettingsFile = Join-Path $SettingsDir 'settings.json'

function Get-DefaultSettings {
    [ordered]@{
        RecordMinutes   = 10
        RemoteFolder    = 'C:\PerfLogs\DefenderPerf'
        Instance        = 'DefenderPerfGui'
        CancelExisting  = $false
        FallbackProfile = $true
        DeleteRemote    = $true
        UseCredential   = $false
        ThrottleLimit   = 32
        AnalyzeLocation = 'Lokal'
        Top             = 25
        TopPathsDepth   = 4
        TopScans        = 5000
        CompareTop      = 25
        DurationUnit    = 'Ticks'
        WorkerRegex     = '^(?<Worker>[^_]+)'
        CollectFolder   = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'DefenderPerf'
        ExportCsv       = $true
        ExportExcel     = $false
        CsvDelimiter    = ';'
        Servers         = ''
        Upn             = ''
        EndpointOnly    = $true
        DisableWam      = $false
        ResMinutes      = 10
        ResIntervalSec  = 5
        ResTopN         = 25
        DefenderShareWarn = 15
        CatDefender     = '^(MsMpEng|MsMpEngCP|MpDefenderCoreService|NisSrv|MpCmdRun|MsSense|SenseCnCProxy|SenseIR|SenseNdr|SenseTVM|SenseCE|SenseSampleUploader|SenseImdsCollector|SenseM365|MpDlpService|MpDlpCmd)$'
        CatCitrix       = '^(ctx|citrix|wfshell|wfcrun|wfica|pica|brokeragent|cdfsvc|upmsvc|hdx|selfservice|receiver|concentr|redirector|authmansvr|vdaredirector|icast)'
        CatFslogix      = '^frx'
        CatOffice       = '^(winword|excel|powerpnt|outlook|olk|onenote|msaccess|mspub|visio|winproj|lync|teams|ms-teams|msteams|officeclicktorun|onedrive|filecoauth|officesvcmgr)$'
        CatBrowser      = '^(msedge|msedgewebview2|chrome|firefox|iexplore)$'
        CatWindows      = '^(system|registry|memory compression|smss|csrss|wininit|winlogon|services|lsass|svchost|dwm|explorer|spoolsv|searchindexer|searchhost|searchprotocolhost|searchfilterhost|wmiprvse|tiworker|trustedinstaller|runtimebroker|sihost|taskhostw|ctfmon|shellexperiencehost|startmenuexperiencehost|textinputhost|conhost|fontdrvhost|logonui|audiodg|dllhost|rdpclip|wsmprovhost|lsaiso|vmmem)$'
    }
}

function Load-Settings {
    $s = Get-DefaultSettings
    if (Test-Path $SettingsFile) {
        try {
            $j = Get-Content $SettingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($p in $j.PSObject.Properties) { if ($s.Contains($p.Name)) { $s[$p.Name] = $p.Value } }
        }
        catch { Write-Log "Einstellungen konnten nicht gelesen werden: $($_.Exception.Message)" 'WARN' }
    }
    return $s
}

function Save-Settings {
    param($Settings)
    $null = New-Item -ItemType Directory -Path $SettingsDir -Force
    $Settings | ConvertTo-Json | Set-Content -Path $SettingsFile -Encoding UTF8
}

function Select-ComboByTag {
    param($Combo, [string]$Tag)
    foreach ($item in $Combo.Items) { if ("$($item.Tag)" -eq $Tag) { $Combo.SelectedItem = $item; return } }
    $Combo.SelectedIndex = 0
}

function Set-UiFromSettings {
    param($s)
    $ui.txtRecordMinutes.Text      = "$($s.RecordMinutes)"
    $ui.txtRemoteFolder.Text       = $s.RemoteFolder
    $ui.txtInstance.Text           = $s.Instance
    $ui.chkCancelExisting.IsChecked  = [bool]$s.CancelExisting
    $ui.chkFallbackProfile.IsChecked = [bool]$s.FallbackProfile
    $ui.chkDeleteRemote.IsChecked    = [bool]$s.DeleteRemote
    $ui.chkUseCredential.IsChecked   = [bool]$s.UseCredential
    $ui.txtThrottle.Text           = "$($s.ThrottleLimit)"
    Select-ComboByTag $ui.cmbAnalyzeLocation $s.AnalyzeLocation
    $ui.txtTop.Text                = "$($s.Top)"
    $ui.txtDepth.Text              = "$($s.TopPathsDepth)"
    $ui.txtTopScans.Text           = "$($s.TopScans)"
    $ui.txtCompareTop.Text         = "$($s.CompareTop)"
    Select-ComboByTag $ui.cmbDurationUnit $s.DurationUnit
    $ui.txtWorkerRegex.Text        = $s.WorkerRegex
    $ui.txtCollectFolder.Text      = $s.CollectFolder
    $ui.chkExportCsv.IsChecked     = [bool]$s.ExportCsv
    $ui.chkExportExcel.IsChecked   = [bool]$s.ExportExcel
    $ui.txtCsvDelimiter.Text       = $s.CsvDelimiter
    $ui.txtUpn.Text                = $s.Upn
    $ui.chkEndpointOnly.IsChecked  = [bool]$s.EndpointOnly
    $ui.chkDisableWam.IsChecked    = [bool]$s.DisableWam
    $ui.txtResMinutes.Text         = "$($s.ResMinutes)"
    $ui.txtResInterval.Text        = "$($s.ResIntervalSec)"
    $ui.txtResTopN.Text            = "$($s.ResTopN)"
    $ui.txtResWarn.Text            = "$($s.DefenderShareWarn)"
    $ui.txtCatDefender.Text        = $s.CatDefender
    $ui.txtCatCitrix.Text          = $s.CatCitrix
    $ui.txtCatFslogix.Text         = $s.CatFslogix
    $ui.txtCatOffice.Text          = $s.CatOffice
    $ui.txtCatBrowser.Text         = $s.CatBrowser
    $ui.txtCatWindows.Text         = $s.CatWindows
}

function Get-SettingsFromUi {
    # Liest und validiert alle Einstellungen; bei Fehlern Meldung und $null
    $errors = New-Object System.Collections.Generic.List[string]
    function Get-Int([string]$text, [string]$label, [int]$min, [int]$max) {
        $v = 0
        if (-not [int]::TryParse($text.Trim(), [ref]$v) -or $v -lt $min -or $v -gt $max) {
            $errors.Add("$label muss eine Zahl zwischen $min und $max sein."); return $min
        }
        return $v
    }
    $s = Get-DefaultSettings
    $s.RecordMinutes   = Get-Int $ui.txtRecordMinutes.Text 'Dauer (Minuten)' 1 240
    $s.RemoteFolder    = $ui.txtRemoteFolder.Text.Trim()
    $s.Instance        = $ui.txtInstance.Text.Trim()
    $s.CancelExisting  = [bool]$ui.chkCancelExisting.IsChecked
    $s.FallbackProfile = [bool]$ui.chkFallbackProfile.IsChecked
    $s.DeleteRemote    = [bool]$ui.chkDeleteRemote.IsChecked
    $s.UseCredential   = [bool]$ui.chkUseCredential.IsChecked
    $s.ThrottleLimit   = Get-Int $ui.txtThrottle.Text 'Max. parallele Verbindungen' 1 256
    $s.AnalyzeLocation = "$($ui.cmbAnalyzeLocation.SelectedItem.Tag)"
    $s.Top             = Get-Int $ui.txtTop.Text 'Top-Eintraege' 1 1000
    $s.TopPathsDepth   = Get-Int $ui.txtDepth.Text 'Pfadtiefe' 1 20
    $s.TopScans        = Get-Int $ui.txtTopScans.Text 'Einzelscans pro Worker' 1 100000
    $s.CompareTop      = Get-Int $ui.txtCompareTop.Text 'Zeilen in Vergleichstabellen' 1 500
    $s.DurationUnit    = "$($ui.cmbDurationUnit.SelectedItem.Tag)"
    $s.WorkerRegex     = $ui.txtWorkerRegex.Text.Trim()
    $s.CollectFolder   = $ui.txtCollectFolder.Text.Trim()
    $s.ExportCsv       = [bool]$ui.chkExportCsv.IsChecked
    $s.ExportExcel     = [bool]$ui.chkExportExcel.IsChecked
    $s.CsvDelimiter    = $ui.txtCsvDelimiter.Text
    $s.Servers         = $ui.txtServers.Text
    $s.Upn             = $ui.txtUpn.Text.Trim()
    $s.EndpointOnly    = [bool]$ui.chkEndpointOnly.IsChecked
    $s.DisableWam      = [bool]$ui.chkDisableWam.IsChecked
    $s.ResMinutes      = Get-Int $ui.txtResMinutes.Text 'Ressourcenmessung: Dauer (Minuten)' 1 480
    $s.ResIntervalSec  = Get-Int $ui.txtResInterval.Text 'Ressourcenmessung: Intervall (Sekunden)' 2 300
    $s.ResTopN         = Get-Int $ui.txtResTopN.Text 'Top-Prozesse pro Worker' 5 500
    $s.DefenderShareWarn = Get-Int $ui.txtResWarn.Text 'Warnschwelle Defender-Anteil' 1 100
    $catMap = [ordered]@{ CatDefender = 'Defender'; CatCitrix = 'Citrix'; CatFslogix = 'FSLogix'; CatOffice = 'Office / M365'; CatBrowser = 'Browser'; CatWindows = 'Windows / System' }
    foreach ($k in $catMap.Keys) {
        $val = $ui["txt$k"].Text.Trim()
        $s[$k] = $val
        if ($val) { try { $null = [regex]::new($val) } catch { $errors.Add("Regex fuer Kategorie '$($catMap[$k])' ist ungueltig.") } }
    }
    if (-not $s.CatDefender) { $errors.Add('Regex fuer Kategorie Defender darf nicht leer sein.') }

    if ($s.RemoteFolder -notmatch '^[A-Za-z]:\\') { $errors.Add('Ablageordner auf dem Worker muss ein lokaler Pfad sein (z.B. C:\PerfLogs\DefenderPerf).') }
    if ($s.Instance -notmatch '^[\w\-]+$') { $errors.Add('WPR-Instanzname darf nur Buchstaben, Zahlen, - und _ enthalten.') }
    if (-not $s.CollectFolder) { $errors.Add('Sammelordner fehlt.') }
    if ($s.CsvDelimiter.Length -ne 1) { $errors.Add('CSV-Trennzeichen muss genau ein Zeichen sein.') }
    try { $null = [regex]::new($s.WorkerRegex) } catch { $errors.Add('Worker-Regex ist ungueltig.') }

    if ($errors.Count) {
        [System.Windows.MessageBox]::Show(($errors -join "`n"), 'Einstellungen pruefen', 'OK', 'Warning') | Out-Null
        $ui.tabMain.SelectedItem = $ui.tabSettings
        return $null
    }
    return $s
}
#endregion

#region Hilfsfunktionen GUI
function Get-ServerList {
    $list = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($ui.txtServers.Text -split "`r?`n")) {
        $l = ($line -replace '#.*$', '').Trim()
        if (-not $l) { continue }
        foreach ($part in ($l -split '[,;\s]+')) {
            if ($part -and $seen.Add($part)) { $list.Add($part) }
        }
    }
    return $list.ToArray()
}

function Initialize-ServerStatus {
    param([string[]]$Servers)
    $sync.Servers.Clear()
    foreach ($s in $Servers) {
        [void]$sync.Servers.Add([pscustomobject]@{
            Server = $s; Worker = (Get-ShortName $s); Status = '-'; Plattform = ''; Profil = ''; ETL_MB = $null; Meldung = ''
        })
    }
    $ui.gridServers.ItemsSource = $null
    $ui.gridServers.ItemsSource = $sync.Servers
}

function Set-Grid {
    param($Grid, $Data)
    $oc = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($d in @($Data)) { if ($null -ne $d) { $oc.Add($d) } }
    foreach ($c in $Grid.Columns) { $c.SortDirection = $null }   # Sortierpfeil zuruecksetzen (neue Daten)
    $Grid.ItemsSource = $oc
}

function Get-Credentials {
    param($Settings)
    if (-not $Settings.UseCredential) { return $null }
    $c = Get-Credential -Message 'Anmeldedaten fuer die Citrix-Worker'
    if (-not $c) { Write-Log 'Keine Anmeldedaten eingegeben – abgebrochen.' 'WARN' }
    return $c
}

$script:bg = $null
function Start-BackgroundTask {
    param([scriptblock]$Work, [hashtable]$TaskArgs, [switch]$STA)
    if ($sync.Busy) { return }
    $sync.Busy = $true; $sync.Cancel = $false; $sync.StopNow = $false; $sync.Progress = 0; $sync.ProgressText = ''
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = $(if ($STA) { 'STA' } else { 'MTA' })   # STA fuer interaktive Anmeldung (Purview)
    $rs.ThreadOptions = 'ReuseThread'
    $rs.Open()
    $rs.SessionStateProxy.SetVariable('sync', $sync)
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript({
        param($CoreText, $WorkText, $TaskArgs)
        try {
            . ([scriptblock]::Create($CoreText))
            & ([scriptblock]::Create($WorkText)) $TaskArgs
        }
        catch { Write-Log "Unerwarteter Fehler: $($_.Exception.Message)" 'ERROR' }
        finally { $sync.Busy = $false; $sync.ProgressText = '' }
    }.ToString()).AddArgument($CoreBlock.ToString()).AddArgument($Work.ToString()).AddArgument($TaskArgs)
    $script:bg = @{ PS = $ps; RS = $rs; Handle = $ps.BeginInvoke() }
}

$script:lastBusy = $null
function Update-ButtonState {
    $busy = [bool]$sync.Busy
    if ($script:lastBusy -eq $busy) { return }
    $script:lastBusy = $busy
    foreach ($n in 'btnStart', 'btnTest', 'btnAnalyzeFolder', 'btnAnalyzeFiles', 'btnLoadServers', 'btnSaveSettings', 'btnResetSettings', 'btnFeatures', 'btnDlpLoad', 'btnResStart') { $ui[$n].IsEnabled = -not $busy }
    foreach ($n in 'btnStopNow', 'btnCancel', 'btnResStop', 'btnResCancel') { $ui[$n].IsEnabled = $busy }
    $ui.txtServers.IsReadOnly = $busy
}

$script:Results = $null
$script:DetailWorker = '(alle)'
$script:DetailText = ''
$script:DetailPredicate = [Predicate[object]] {
    param($o)
    if ($script:DetailWorker -and $script:DetailWorker -ne '(alle)' -and "$($o.Worker)" -ne $script:DetailWorker) { return $false }
    if ([string]::IsNullOrWhiteSpace($script:DetailText)) { return $true }
    foreach ($p in $o.PSObject.Properties) { if ("$($p.Value)" -like "*$($script:DetailText)*") { return $true } }
    return $false
}

function Update-DetailView {
    if (-not $script:Results) { return }
    $key = "$($ui.cmbDetailSet.SelectedItem.Tag)"
    if (-not $key) { $key = 'AllScans' }
    Set-Grid $ui.gridDetails $script:Results[$key]
    Update-DetailFilter
}

function Update-DetailFilter {
    if (-not $ui.gridDetails.ItemsSource) { $ui.lblDetailCount.Text = ''; return }
    $script:DetailWorker = "$($ui.cmbDetailWorker.SelectedItem)"
    $script:DetailText = $ui.txtDetailFilter.Text
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridDetails.ItemsSource)
    $view.Filter = $script:DetailPredicate
    $view.Refresh()
    $c = 0; foreach ($x in $view) { $c++ }
    $ui.lblDetailCount.Text = "$c Eintraege"
}

function Show-Results {
    param($r)
    $script:Results = $r
    Set-Grid $ui.gridSummary $r.Summary
    Set-Grid $ui.gridPaths $r.CmpPaths
    Set-Grid $ui.gridProcs $r.CmpProcs
    Set-Grid $ui.gridExts $r.CmpExts
    $ui.txtHints.Text = $r.Hints
    $ui.cmbDetailWorker.Items.Clear()
    [void]$ui.cmbDetailWorker.Items.Add('(alle)')
    foreach ($w in @($r.Workers)) { [void]$ui.cmbDetailWorker.Items.Add($w) }
    $ui.cmbDetailWorker.SelectedIndex = 0
    $ui.txtDetailFilter.Text = ''
    Update-DetailView
    $metric = if ($r.MetricName -eq 'Scanzeit_s_pro_Min') { 'Scanzeit pro Minute' } else { 'Scanzeit total' }
    $ui.lblResultInfo.Text = ('{0} Worker · Balken = relative {1} · {2:dd.MM.yyyy HH:mm} · {3}' -f @($r.Workers).Count, $metric, $r.Created, $r.OutputFolder)
    $ui.tabMain.SelectedItem = $ui.tabResults
}

function Select-Folder {
    param([string]$Description, [string]$Start)
    $d = New-Object System.Windows.Forms.FolderBrowserDialog
    $d.Description = $Description
    if ($Start -and (Test-Path $Start)) { $d.SelectedPath = $Start }
    if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $d.SelectedPath }
    return $null
}

# Spaltenkoepfe: Unterstriche als Leerzeichen anzeigen (WPF verschluckt sonst das erste "_"), Hilfsspalte ausblenden
$autoGen = {
    param($sender, $e)
    if ($e.PropertyName -in 'Anteil_Prozent', 'Raw', 'Markierung') { $e.Cancel = $true; return }
    $e.Column.Header = ($e.PropertyName -replace '_', ' ')
    $e.Column.CanUserSort = $true
    $e.Column.SortMemberPath = $e.PropertyName
    if ($e.Column -is [System.Windows.Controls.DataGridTextColumn] -and $e.PropertyName -in 'Wert', 'Bedingungen', 'Endpoint_Aktionen', 'Hinweis') {
        $e.Column.MaxWidth = 520
    }
}
# Sortierung per Klick auf den Spaltenkopf (1. Klick aufsteigend, 2. Klick absteigend); Filter bleiben erhalten
$sortHandler = {
    param($sender, $e)
    $e.Handled = $true
    $col = $e.Column
    $prop = $col.SortMemberPath
    if (-not $prop -or -not $sender.ItemsSource) { return }
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($sender.ItemsSource) -as [System.Windows.Data.ListCollectionView]
    if (-not $view) { return }
    $desc = ($col.SortDirection -eq [System.ComponentModel.ListSortDirection]::Ascending)
    try {
        $view.CustomSort = New-Object DefPerfGui.PSPropertyComparer($prop, $desc)
        foreach ($c in $sender.Columns) { if ($c -ne $col) { $c.SortDirection = $null } }
        $col.SortDirection = $(if ($desc) { [System.ComponentModel.ListSortDirection]::Descending } else { [System.ComponentModel.ListSortDirection]::Ascending })
    }
    catch { $ui.lblStatus.Text = "Sortierung nicht moeglich: $($_.Exception.Message)" }
}

foreach ($g in 'gridServers', 'gridSummary', 'gridPaths', 'gridProcs', 'gridExts', 'gridDetails', 'gridFeatures', 'gridDlp',
               'gridResSummary', 'gridResPivot', 'gridResCats', 'gridResProcs', 'gridResTicks') {
    $ui[$g].Add_AutoGeneratingColumn($autoGen)
    $ui[$g].CanUserSortColumns = $true
    $ui[$g].Add_Sorting($sortHandler)
}

#----- Defender-Features: Ansicht, Filter, Details -----
$script:FeatResults = $null
$script:FeatText = ''; $script:FeatDiff = $false; $script:FeatWarn = $false
$script:FeatPredicate = [Predicate[object]] {
    param($o)
    if ($script:FeatDiff -and $o.PSObject.Properties['Abweichung'] -and $o.Abweichung -ne 'ja') { return $false }
    if ($script:FeatWarn -and $o.Bewertung -notin 'Warnung', 'Fehler') { return $false }
    if ([string]::IsNullOrWhiteSpace($script:FeatText)) { return $true }
    foreach ($p in $o.PSObject.Properties) { if ("$($p.Value)" -like "*$($script:FeatText)*") { return $true } }
    return $false
}

function Update-FeatureView {
    if (-not $script:FeatResults) { return }
    $data = switch ($ui.cmbFeatView.SelectedIndex) { 1 { $script:FeatResults.Matrix } 2 { $script:FeatResults.List } default { $script:FeatResults.Overview } }
    $ui.chkFeatDiffOnly.IsEnabled = ($ui.cmbFeatView.SelectedIndex -eq 1)
    Set-Grid $ui.gridFeatures $data
    Update-FeatureFilter
}

function Update-FeatureFilter {
    if (-not $ui.gridFeatures.ItemsSource) { $ui.lblFeatCount.Text = ''; return }
    $script:FeatText = $ui.txtFeatFilter.Text
    $script:FeatDiff = [bool]$ui.chkFeatDiffOnly.IsChecked -and $ui.cmbFeatView.SelectedIndex -eq 1
    $script:FeatWarn = [bool]$ui.chkFeatWarnOnly.IsChecked
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridFeatures.ItemsSource)
    $view.Filter = $script:FeatPredicate
    $view.Refresh()
    $c = 0; foreach ($x in $view) { $c++ }
    $ui.lblFeatCount.Text = "$c Zeilen · $(@($script:FeatResults.Workers).Count) Worker · $('{0:dd.MM.yyyy HH:mm}' -f $script:FeatResults.Created)"
}

function Show-FeatureResults {
    param($r)
    $script:FeatResults = $r
    Update-FeatureView
    $ui.tabMain.SelectedItem = $ui.tabFeatures
}

#----- DLP: Ansicht, Filter, Details -----
$script:DlpRows = $null
$script:DlpText = ''; $script:DlpActive = $false
$script:DlpPredicate = [Predicate[object]] {
    param($o)
    if ($script:DlpActive -and $o.Bewertung -eq 'Aus') { return $false }
    if ([string]::IsNullOrWhiteSpace($script:DlpText)) { return $true }
    foreach ($p in $o.PSObject.Properties) {
        if ($p.Name -eq 'Raw') { continue }
        if ("$($p.Value)" -like "*$($script:DlpText)*") { return $true }
    }
    return $false
}

function Update-DlpFilter {
    if (-not $ui.gridDlp.ItemsSource) { $ui.lblDlpCount.Text = ''; return }
    $script:DlpText = $ui.txtDlpFilter.Text
    $script:DlpActive = [bool]$ui.chkDlpActiveOnly.IsChecked
    $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridDlp.ItemsSource)
    $view.Filter = $script:DlpPredicate
    $view.Refresh()
    $c = 0; foreach ($x in $view) { $c++ }
    $pol = @($script:DlpRows | Where-Object { $_.Richtlinie -notlike '(*' } | ForEach-Object Richtlinie | Select-Object -Unique).Count
    $ui.lblDlpCount.Text = "$c Zeilen · $pol Richtlinie(n)"
}

function Show-DlpResults {
    param($rows)
    $script:DlpRows = @($rows)
    Set-Grid $ui.gridDlp $rows
    $ui.txtDlpDetail.Text = ''
    Update-DlpFilter
    $ui.tabMain.SelectedItem = $ui.tabDlp
}

function Format-RowDetail {
    param($o)
    if ($null -eq $o) { return '' }
    $lines = foreach ($p in $o.PSObject.Properties) {
        if ($p.Name -eq 'Raw') { continue }
        $v = "$($p.Value)"
        if ($v -match '; ' -and $v.Length -gt 100) { $v = "`r`n    " + ($v -replace '; ', "`r`n    ") }
        '{0,-28}: {1}' -f ($p.Name -replace '_', ' '), $v
    }
    return ($lines -join "`r`n")
}

#----- Ressourcen: Anzeige und Filter -----
$script:ResResults = $null

function Update-ResFilter {
    if (-not $script:ResResults) { $ui.lblResInfo.Text = ''; return }
    $w = "$($ui.cmbResWorker.SelectedItem)"
    if (-not $w) { $w = '(alle)' }
    $t = $ui.txtResFilter.Text
    $d = [bool]$ui.chkResDefOnly.IsChecked
    $pred = [Predicate[object]]({
        param($o)
        if ($w -ne '(alle)' -and $o.PSObject.Properties['Worker'] -and "$($o.Worker)" -ne $w) { return $false }
        if ($d -and $o.PSObject.Properties['Kategorie'] -and $o.Kategorie -ne 'Defender') { return $false }
        if ([string]::IsNullOrWhiteSpace($t)) { return $true }
        foreach ($p in $o.PSObject.Properties) { if ("$($p.Value)" -like "*$t*") { return $true } }
        return $false
    }.GetNewClosure())
    foreach ($g in 'gridResCats', 'gridResProcs', 'gridResTicks') {
        if (-not $ui[$g].ItemsSource) { continue }
        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui[$g].ItemsSource)
        $view.Filter = $pred
        $view.Refresh()
    }
    $c = 0
    if ($ui.gridResProcs.ItemsSource) { foreach ($x in [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.gridResProcs.ItemsSource)) { $c++ } }
    $ui.lblResInfo.Text = ('{0} Worker · {1} Prozesszeilen sichtbar · {2:dd.MM.yyyy HH:mm}' -f @($script:ResResults.Workers).Count, $c, $script:ResResults.Created)
}

function Show-ResResults {
    param($r)
    $script:ResResults = $r
    Set-Grid $ui.gridResSummary $r.Summary
    Set-Grid $ui.gridResPivot $r.CatPivot
    Set-Grid $ui.gridResCats $r.Cats
    Set-Grid $ui.gridResProcs $r.Procs
    Set-Grid $ui.gridResTicks $r.Ticks
    $ui.txtResHints.Text = $r.Hints
    $ui.cmbResWorker.Items.Clear()
    [void]$ui.cmbResWorker.Items.Add('(alle)')
    foreach ($w in @($r.Workers)) { [void]$ui.cmbResWorker.Items.Add($w) }
    $ui.cmbResWorker.SelectedIndex = 0
    Update-ResFilter
    $ui.tabMain.SelectedItem = $ui.tabRes
}
#endregion

#region Ereignisse
$ui.btnLoadServers.Add_Click({
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'Text/CSV (*.txt;*.csv)|*.txt;*.csv|Alle Dateien (*.*)|*.*'
    if ($d.ShowDialog()) {
        $names = foreach ($line in (Get-Content -LiteralPath $d.FileName)) {
            $first = (($line -split '[,;\t]')[0]).Trim().Trim('"')
            if ($first -and $first -notmatch '^(server|name|computer|computername|hostname|machinename)$') { $first }
        }
        $existing = $ui.txtServers.Text.TrimEnd()
        $ui.txtServers.Text = (@($existing) + @($names) | Where-Object { $_ }) -join "`r`n"
        Write-Log "$(@($names).Count) Server aus $($d.FileName) geladen"
    }
})

$ui.btnTest.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $servers = Get-ServerList
    if (-not $servers) { [System.Windows.MessageBox]::Show('Bitte mindestens einen Server eingeben.', 'Server', 'OK', 'Information') | Out-Null; return }
    $cred = Get-Credentials $s; if ($s.UseCredential -and -not $cred) { return }
    Initialize-ServerStatus $servers
    Start-BackgroundTask -Work { param($a) Invoke-ConnectionTest -A $a } -TaskArgs @{ Servers = $servers; Settings = $s; Credential = $cred }
})

$ui.btnStart.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $servers = Get-ServerList
    if (-not $servers) { [System.Windows.MessageBox]::Show('Bitte mindestens einen Server eingeben.', 'Server', 'OK', 'Information') | Out-Null; return }
    if ($s.AnalyzeLocation -eq 'Lokal' -and -not (Get-Command Get-MpPerformanceReport -ErrorAction SilentlyContinue)) {
        $a = [System.Windows.MessageBox]::Show("Get-MpPerformanceReport ist auf diesem PC nicht verfuegbar.`nDie Auswertung wird deshalb auf den Workern ausgefuehrt. Fortfahren?", 'Auswertung', 'YesNo', 'Question')
        if ($a -ne 'Yes') { return }
    }
    $msg = "Aufnahme auf $($servers.Count) Server(n) fuer $($s.RecordMinutes) Minuten starten?`n`nAblage: $($s.CollectFolder)"
    if ([System.Windows.MessageBox]::Show($msg, 'Aufnahme starten', 'YesNo', 'Question') -ne 'Yes') { return }
    $cred = Get-Credentials $s; if ($s.UseCredential -and -not $cred) { return }
    try { Save-Settings $s } catch {}
    Initialize-ServerStatus $servers
    Start-BackgroundTask -Work { param($a) Invoke-RecordingWorkflow -A $a } -TaskArgs @{ Servers = $servers; Settings = $s; Credential = $cred }
})

$ui.btnStopNow.Add_Click({
    $sync.StopNow = $true
    Write-Log 'Aufnahme wird vorzeitig beendet und ausgewertet...'
})

$ui.btnCancel.Add_Click({
    if ([System.Windows.MessageBox]::Show('Laufenden Vorgang abbrechen? Aufnahmen werden verworfen.', 'Abbrechen', 'YesNo', 'Warning') -eq 'Yes') {
        $sync.Cancel = $true
        Write-Log 'Abbruch angefordert...' 'WARN'
    }
})

$ui.btnAnalyzeFolder.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $folder = Select-Folder -Description 'Ordner mit ETL-Dateien waehlen' -Start $s.CollectFolder
    if (-not $folder) { return }
    $files = @(Get-ChildItem -Path $folder -Filter *.etl -File | Sort-Object Name | ForEach-Object FullName)
    if (-not $files) { [System.Windows.MessageBox]::Show('Keine .etl-Dateien im gewaehlten Ordner.', 'ETL', 'OK', 'Information') | Out-Null; return }
    Start-BackgroundTask -Work { param($a) Invoke-FolderAnalysis -A $a } -TaskArgs @{ Files = $files; Settings = $s }
})

$ui.btnAnalyzeFiles.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $d = New-Object Microsoft.Win32.OpenFileDialog
    $d.Filter = 'ETL-Aufnahmen (*.etl)|*.etl'
    $d.Multiselect = $true
    if (Test-Path $s.CollectFolder) { $d.InitialDirectory = $s.CollectFolder }
    if (-not $d.ShowDialog()) { return }
    $files = @($d.FileNames | Sort-Object)
    Start-BackgroundTask -Work { param($a) Invoke-FolderAnalysis -A $a } -TaskArgs @{ Files = $files; Settings = $s }
})

$ui.btnExport.Add_Click({
    if (-not $script:Results) { [System.Windows.MessageBox]::Show('Noch keine Ergebnisse vorhanden.', 'Export', 'OK', 'Information') | Out-Null; return }
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $s.ExportCsv = $true
    $folder = Select-Folder -Description 'Zielordner fuer den Export' -Start $script:Results.OutputFolder
    if (-not $folder) { return }
    try {
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
        $files = Export-Results -Results $script:Results -Folder $folder -Settings $s
        $script:Results.OutputFolder = $folder
        Write-Log "Export: $($files.Count) Datei(en) nach $folder"
        [System.Windows.MessageBox]::Show("$($files.Count) Datei(en) exportiert nach:`n$folder", 'Export', 'OK', 'Information') | Out-Null
    }
    catch { [System.Windows.MessageBox]::Show("Export fehlgeschlagen:`n$($_.Exception.Message)", 'Export', 'OK', 'Error') | Out-Null }
    finally { $window.Cursor = $null }
})

$ui.btnOpenFolder.Add_Click({
    $f = $null
    if ($script:Results) { $f = $script:Results.OutputFolder }
    if (-not $f -or -not (Test-Path $f)) { $f = $ui.txtCollectFolder.Text }
    if ($f -and (Test-Path $f)) { Start-Process explorer.exe -ArgumentList "`"$f`"" }
    else { [System.Windows.MessageBox]::Show('Ordner existiert noch nicht.', 'Ordner', 'OK', 'Information') | Out-Null }
})

$ui.btnBrowseCollect.Add_Click({
    $f = Select-Folder -Description 'Sammelordner fuer ETL-Dateien und Auswertungen' -Start $ui.txtCollectFolder.Text
    if ($f) { $ui.txtCollectFolder.Text = $f }
})

$ui.btnSaveSettings.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    try { Save-Settings $s; Write-Log "Einstellungen gespeichert: $SettingsFile" }
    catch { [System.Windows.MessageBox]::Show("Speichern fehlgeschlagen:`n$($_.Exception.Message)", 'Einstellungen', 'OK', 'Error') | Out-Null }
})

$ui.btnResetSettings.Add_Click({
    if ([System.Windows.MessageBox]::Show('Alle Einstellungen (ausser Serverliste) auf Standard zuruecksetzen?', 'Standardwerte', 'YesNo', 'Question') -eq 'Yes') {
        Set-UiFromSettings (Get-DefaultSettings)
        Write-Log 'Einstellungen auf Standardwerte gesetzt (noch nicht gespeichert).'
    }
})

$ui.cmbDetailSet.Add_SelectionChanged({ Update-DetailView })
$ui.cmbDetailWorker.Add_SelectionChanged({ Update-DetailFilter })
$ui.txtDetailFilter.Add_TextChanged({ Update-DetailFilter })

#----- Ressourcen: Defender vs. Rest -----
$ui.btnResStart.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $servers = Get-ServerList
    if (-not $servers) {
        [System.Windows.MessageBox]::Show('Bitte im Tab "Server & Aufnahme" mindestens einen Server eingeben.', 'Server', 'OK', 'Information') | Out-Null
        return
    }
    $msg = "Ressourcenmessung auf $($servers.Count) Server(n) fuer $($s.ResMinutes) Minuten (Intervall $($s.ResIntervalSec) s) starten?"
    if ([System.Windows.MessageBox]::Show($msg, 'Ressourcenmessung', 'YesNo', 'Question') -ne 'Yes') { return }
    $cred = Get-Credentials $s; if ($s.UseCredential -and -not $cred) { return }
    try { Save-Settings $s } catch {}
    Initialize-ServerStatus $servers
    Start-BackgroundTask -Work { param($a) Invoke-ResourceMeasurement -A $a } -TaskArgs @{ Servers = $servers; Settings = $s; Credential = $cred }
})

$ui.btnResStop.Add_Click({
    $sync.StopNow = $true
    Write-Log 'Messung wird vorzeitig beendet und ausgewertet...'
})

$ui.btnResCancel.Add_Click({
    if ([System.Windows.MessageBox]::Show('Laufende Messung abbrechen? Es erfolgt keine Auswertung.', 'Abbrechen', 'YesNo', 'Warning') -eq 'Yes') {
        $sync.Cancel = $true
        Write-Log 'Abbruch angefordert...' 'WARN'
    }
})

$ui.btnResExport.Add_Click({
    if (-not $script:ResResults) { [System.Windows.MessageBox]::Show('Noch keine Messung vorhanden.', 'Export', 'OK', 'Information') | Out-Null; return }
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $folder = Select-Folder -Description 'Zielordner fuer den Export der Ressourcenmessung' -Start $s.CollectFolder
    if (-not $folder) { return }
    try {
        $sets = [ordered]@{
            'Ressourcen_Uebersicht'           = $script:ResResults.Summary
            'Ressourcen_Vergleich_Kategorien' = $script:ResResults.CatPivot
            'Ressourcen_Kategorien'           = $script:ResResults.Cats
            'Ressourcen_Prozesse'             = $script:ResResults.Procs
            'Ressourcen_Verlauf'              = $script:ResResults.Ticks
        }
        $files = @(Export-Table -Sets $sets -Folder $folder -Settings $s -XlsxName 'Ressourcen_Defender_vs_Rest.xlsx')
        Set-Content -Path (Join-Path $folder 'Ressourcen_Hinweise.txt') -Value $script:ResResults.Hints -Encoding UTF8
        Write-Log "Ressourcen-Export: $($files.Count + 1) Datei(en) nach $folder"
        [System.Windows.MessageBox]::Show("$($files.Count + 1) Datei(en) exportiert nach:`n$folder", 'Export', 'OK', 'Information') | Out-Null
    }
    catch { [System.Windows.MessageBox]::Show("Export fehlgeschlagen:`n$($_.Exception.Message)", 'Export', 'OK', 'Error') | Out-Null }
})

$ui.cmbResWorker.Add_SelectionChanged({ Update-ResFilter })
$ui.txtResFilter.Add_TextChanged({ Update-ResFilter })
$ui.chkResDefOnly.Add_Click({ Update-ResFilter })

#----- Defender-Features -----
$ui.btnFeatures.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $servers = Get-ServerList
    if (-not $servers) {
        [System.Windows.MessageBox]::Show('Bitte im Tab "Server & Aufnahme" mindestens einen Server eingeben.', 'Server', 'OK', 'Information') | Out-Null
        return
    }
    $cred = Get-Credentials $s; if ($s.UseCredential -and -not $cred) { return }
    Initialize-ServerStatus $servers
    Start-BackgroundTask -Work { param($a) Invoke-FeatureInventory -A $a } -TaskArgs @{ Servers = $servers; Settings = $s; Credential = $cred }
})

$ui.btnFeatExport.Add_Click({
    if (-not $script:FeatResults) { [System.Windows.MessageBox]::Show('Noch keine Features eingelesen.', 'Export', 'OK', 'Information') | Out-Null; return }
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $folder = Select-Folder -Description 'Zielordner fuer den Feature-Export' -Start $s.CollectFolder
    if (-not $folder) { return }
    try {
        $sets = [ordered]@{
            'Defender_Features_Uebersicht' = $script:FeatResults.Overview
            'Defender_Features_Matrix'     = $script:FeatResults.Matrix
            'Defender_Features_Liste'      = $script:FeatResults.List
        }
        $files = Export-Table -Sets $sets -Folder $folder -Settings $s -XlsxName 'Defender_Features.xlsx'
        Write-Log "Feature-Export: $($files.Count) Datei(en) nach $folder"
        [System.Windows.MessageBox]::Show("$($files.Count) Datei(en) exportiert nach:`n$folder", 'Export', 'OK', 'Information') | Out-Null
    }
    catch { [System.Windows.MessageBox]::Show("Export fehlgeschlagen:`n$($_.Exception.Message)", 'Export', 'OK', 'Error') | Out-Null }
})

$ui.cmbFeatView.Add_SelectionChanged({ Update-FeatureView })
$ui.chkFeatDiffOnly.Add_Click({ Update-FeatureFilter })
$ui.chkFeatWarnOnly.Add_Click({ Update-FeatureFilter })
$ui.txtFeatFilter.Add_TextChanged({ Update-FeatureFilter })
$ui.gridFeatures.Add_SelectionChanged({ $ui.txtFeatDetail.Text = Format-RowDetail $ui.gridFeatures.SelectedItem })

#----- DLP (Purview) -----
$ui.btnDlpLoad.Add_Click({
    $s = Get-SettingsFromUi; if (-not $s) { return }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        [System.Windows.MessageBox]::Show("Das Modul ExchangeOnlineManagement fehlt.`n`nInstallation (PowerShell):`nInstall-Module ExchangeOnlineManagement -Scope CurrentUser", 'DLP (Purview)', 'OK', 'Warning') | Out-Null
        return
    }
    try { Save-Settings $s } catch {}
    Start-BackgroundTask -STA -Work { param($a) Invoke-DlpInventory -A $a } -TaskArgs @{ Settings = $s }
})

$ui.btnDlpExport.Add_Click({
    if (-not $script:DlpRows) { [System.Windows.MessageBox]::Show('Noch keine DLP-Regeln eingelesen.', 'Export', 'OK', 'Information') | Out-Null; return }
    $s = Get-SettingsFromUi; if (-not $s) { return }
    $folder = Select-Folder -Description 'Zielordner fuer den DLP-Export' -Start $s.CollectFolder
    if (-not $folder) { return }
    try {
        $files = Export-Table -Sets ([ordered]@{ 'DLP_Richtlinien_Regeln' = $script:DlpRows }) -Folder $folder -Settings $s -XlsxName 'DLP_Richtlinien.xlsx'
        Write-Log "DLP-Export: $($files.Count) Datei(en) nach $folder"
        [System.Windows.MessageBox]::Show("$($files.Count) Datei(en) exportiert nach:`n$folder", 'Export', 'OK', 'Information') | Out-Null
    }
    catch { [System.Windows.MessageBox]::Show("Export fehlgeschlagen:`n$($_.Exception.Message)", 'Export', 'OK', 'Error') | Out-Null }
})

$ui.txtDlpFilter.Add_TextChanged({ Update-DlpFilter })
$ui.chkDlpActiveOnly.Add_Click({ Update-DlpFilter })
$ui.gridDlp.Add_SelectionChanged({
    $o = $ui.gridDlp.SelectedItem
    if ($o) { $ui.txtDlpDetail.Text = (Format-RowDetail $o) + "`r`n`r`n" + ("$($o.Raw)" -replace "(?<!`r)`n", "`r`n") }
    else { $ui.txtDlpDetail.Text = '' }
})

$window.Add_Closing({
    param($sender, $e)
    if ($sync.Busy) {
        $a = [System.Windows.MessageBox]::Show("Ein Vorgang laeuft noch. Trotzdem schliessen?`nLaufende Aufnahmen auf den Workern muessen dann manuell gestoppt werden (wpr -cancel -instancename $($ui.txtInstance.Text)).", 'Beenden', 'YesNo', 'Warning')
        if ($a -ne 'Yes') { $e.Cancel = $true; return }
        $sync.Cancel = $true
    }
    try {
        $s = Get-DefaultSettings
        if (Test-Path $SettingsFile) { $s = Load-Settings }
        $s.Servers = $ui.txtServers.Text
        Save-Settings $s
    } catch {}
})
#endregion

#region Timer (GUI-Aktualisierung)
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(400)
$timer.Add_Tick({
    try {
        $line = $null; $last = $null
        $sb = New-Object System.Text.StringBuilder
        while ($sync.Log.TryDequeue([ref]$line)) { [void]$sb.AppendLine($line); $last = $line }
        if ($sb.Length) {
            $ui.txtLog.AppendText($sb.ToString())
            $ui.txtLog.ScrollToEnd()
            $ui.lblStatus.Text = $last
            if ($sync.LogFile) { try { Add-Content -Path $sync.LogFile -Value $sb.ToString().TrimEnd() -Encoding UTF8 } catch {} }
        }
        if ($sync.ServersDirty) { $sync.ServersDirty = $false; $ui.gridServers.Items.Refresh() }
        $ui.pbProgress.Value = [double]$sync.Progress
        $ui.lblProgress.Text = $sync.ProgressText
        if ($sync.ResultsReady) { $sync.ResultsReady = $false; Show-Results $sync.Results }
        if ($sync.FeatReady) { $sync.FeatReady = $false; Show-FeatureResults $sync.FeatResults }
        if ($sync.DlpReady) { $sync.DlpReady = $false; Show-DlpResults $sync.DlpResults }
        if ($sync.ResReady) { $sync.ResReady = $false; Show-ResResults $sync.ResResults }
        Update-ButtonState
        if (-not $sync.Busy -and $script:bg -and $script:bg.Handle.IsCompleted) {
            try { $script:bg.PS.EndInvoke($script:bg.Handle) | Out-Null } catch {}
            $script:bg.PS.Dispose(); $script:bg.RS.Dispose(); $script:bg = $null
            $ui.pbProgress.Value = 0
        }
    }
    catch { $ui.lblStatus.Text = "GUI-Fehler: $($_.Exception.Message)" }
})
#endregion

#region Start
$settings = Load-Settings
Set-UiFromSettings $settings
$ui.txtServers.Text = $settings.Servers
$ui.lblSettingsPath.Text = $SettingsFile
$ui.gridServers.ItemsSource = $sync.Servers
Update-ButtonState
if (-not (Get-Command Get-MpPerformanceReport -ErrorAction SilentlyContinue)) {
    Write-Log 'Hinweis: Get-MpPerformanceReport ist auf diesem PC nicht verfuegbar – Auswertung nur auf den Workern moeglich.' 'WARN'
}
else { Write-Log 'Bereit.' }
$timer.Start()
[void]$window.ShowDialog()
$timer.Stop()
if ($script:bg) { try { $script:bg.PS.Stop(); $script:bg.PS.Dispose(); $script:bg.RS.Dispose() } catch {} }
#endregion
