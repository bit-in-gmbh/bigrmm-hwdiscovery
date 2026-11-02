# Sicherheits- und Hardeningdurchlauf vom 2. November 2026

## Umfang und Einordnung

Geprüft wurden die lokalen Windows-, Linux- und macOS-Collector, Parser, Abhängigkeiten und der GitHub-Actions-Workflow. Ausgangspunkt war Commit `fdc96c6`. Die Bibliothek liest lokale Hardwaremetadaten, startet keine externen Programme und besitzt weder einen Netzwerkdienst noch einen konfigurierbaren Fernzugriff. Die öffentliche Go-API und das JSON-Schema bleiben unverändert; es kamen keine Laufzeitabhängigkeiten hinzu.

Die Befunde betreffen hauptsächlich Ressourcenverbrauch und falsche Inventarwerte bei beschädigten oder manipulierten Firmware-, Treiber- und Kernelangaben. Eine entfernte Ausnutzbarkeit wurde nicht nachgewiesen. Änderungen bleiben auf vorhandene Leser und Collector beschränkt; zusätzliche Dienste, Konfiguration und Abstraktionsschichten wurden nicht eingeführt.

## Behobene Befunde

| Bereich | Befund | Änderung |
| --- | --- | --- |
| Linux | Unbeschränkte `os.ReadFile`-Aufrufe konnten übergroße Metadaten vollständig einlesen; Spezialdateien konnten blockieren. | Gemeinsamer kleiner Leser mit `O_NONBLOCK`, Prüfung auf reguläre Dateien und Längenprüfung vor und während des Lesens. Dateien am Limit bleiben erhalten, größere werden vollständig ausgelassen. |
| Linux | Einzelne sysfs-Ziele wurden erst nach einem Lesezugriff auf die Wurzelgrenze geprüft; udev-Dateinamen enthielten ungeprüfte Metadaten. | Wurzelprüfung vor dem Lesen an den betroffenen Stellen; udev-Schlüssel dürfen keine Pfadkomponenten enthalten. |
| macOS | `hw.packages` konnte eine praktisch unbeschränkte Go-Allokation auslösen. | Höchstens 1024 CPU-Pakete, zusätzlich Abgleich mit verfügbaren physischen und logischen CPU-Zahlen. Andere Inventarbereiche bleiben bei ungültiger Topologie erhalten. |
| macOS | Native Textpuffer wuchsen ohne fachliche Obergrenze; ein fehlgeschlagener Teilappend konnte unvollständige Zeilen hinterlassen. | Grenzen pro Eigenschaft und Collector. Bei Limit oder Allokationsfehler wird die aktuelle Zeile verworfen; frühere vollständige Zeilen bleiben erhalten und weitere Appends sind gesperrt. |
| macOS | Negative `CFNumber`-Werte und `strtoull`-Überläufe konnten als positive Ganzzahlen erscheinen. | Vorzeichen-, Syntax- und `ERANGE`-Prüfung. |
| Windows | Eine überlaufende Summe von DIMM-Kapazitäten lieferte einen irreführenden Teilgesamtwert. | Nur der abgeleitete Gesamtwert wird bei Überlauf ausgelassen; Module und eine unabhängig gemeldete Systemspeichergröße bleiben erhalten. |
| Windows | Zu große Chassiswerte konnten durch Verengung auf `uint16` einen gültigen Typ vortäuschen. | Wertebereich vor der Konvertierung geprüft. |
| Build und CI | Alte Go-Patchversion, bewegliche Action-Tags und unnötig persistierte Checkout-Zugangsdaten. | Go 1.27.3, vollständige Action-Commit-Pins, `persist-credentials: false`, Jobzeitlimits, `go mod verify` und gepinntes `govulncheck` in der bestehenden Betriebssystemmatrix. |

Die Linux-Limits betragen 64 KiB je Einzelattribut, DMI-Einzelrecord, udev-Datei beziehungsweise `meminfo` und 32 MiB für `cpuinfo`, `mountinfo` und `pci.ids`. Die Lesebegrenzung berücksichtigt auch procfs/sysfs-Dateien mit gemeldeter Größe null. Native macOS-Eigenschaften erhalten bis zu 1 MiB Puffer; je Collector sind einschließlich Terminierung 16 MiB vorgesehen. Die SMBIOS-Tabelle war bereits auf 16 MiB begrenzt. Außergewöhnlich große Metadaten können damit fehlen; es wird kein abgeschnittener Inhalt als vollständiger Datensatz ausgegeben.

Die Go-Patchanhebung berücksichtigt die in der offiziellen [Go-Releasehistorie](https://go.dev/doc/devel/release) dokumentierten Sicherheitskorrekturen von 1.27.2 und 1.27.3. Die bestehenden Action-Hauptversionen wurden beibehalten: [checkout v4.4.0](https://github.com/actions/checkout/releases/tag/v4.4.0) mit `11d5960a326750d5838078e36cf38b85af677262` und [setup-go v5.6.0](https://github.com/actions/setup-go/releases/tag/v5.6.0) mit `40f1582b2485089dde7abd97c1529aa768e1baff`. Die Zuordnung wurde gegen die offiziellen Git-Tags geprüft. Der Workflow behält `contents: read` und die unprivilegierten `push`-/`pull_request`-Trigger.

## Prüfstand

Umgebung: Windows 11 Pro x64, Version `10.0.26200`; Go `1.27.3`; GCC `16.2.0` aus MSYS2 für den isolierten C-Helfertest. Alle Angaben beziehen sich auf diesen Durchlauf am 2. November 2026.

| Status | Prüfung | Ergebnis |
| --- | --- | --- |
| Nachgewiesen | `gofmt -l .`, `git diff --check`, abschließender gestagter Diff | Keine Formatierungs- oder Whitespacefehler; auch neue Dateien geprüft. |
| Nachgewiesen | Windows/amd64: `go test -count=1 ./...` | Alle Tests einschließlich des vorhandenen lokalen WMI-Smokes bestanden. Der Smoke prüft Aufruf und JSON-Kodierbarkeit, keine vollständige Richtigkeit aller Hardwarewerte. |
| Nachgewiesen | Windows/amd64: `go vet ./...`, `go test -race -short -count=1 ./...` | Bestanden; die Race-Prüfung lässt den Live-Smoke aus. |
| Nachgewiesen | Windows/arm64: `go test -c`; Windows/386: `go test -count=1 ./...` | Arm64-Testprogramm erfolgreich kompiliert; 386-Stub einschließlich Rückgabe eines leeren Inventars ausgeführt. |
| Nachgewiesen | Linux/amd64 und arm64: jeweils `go test -c`, `go vet ./...` mit `CGO_ENABLED=0` | Beide Targets unter Go 1.27.3 erfolgreich geprüft; keine native Ausführung. |
| Nachgewiesen | Darwin/amd64 und arm64: jeweils `go test -c` mit `CGO_ENABLED=0` | Beide Targets unter Go 1.27.3 erfolgreich kompiliert; keine native Ausführung. |
| Nachgewiesen | Linux/386 und FreeBSD/amd64: `go test -c` mit `CGO_ENABLED=0` | Unterstützungsstubs erfolgreich kompiliert. |
| Nachgewiesen | Temporäre Windows-Go-Harnesses | Drei übertragbare Linux-Hardeningprüfungen plus Mountinfo-Unescape und drei Darwin-Fixture-/Regressiontests bestanden. Nur Buildauswahl und nicht verfügbare Systemzugriffe wurden für die temporären Kopien angepasst; kein eigener Produktpfad wurde eingeführt. |
| Nachgewiesen | Temporärer C-Helferharness mit GCC | Extrahierte native Buffer- und Zahlenfunktionen gegen Pufferlimit, NUL-Terminierung, `SIZE_MAX`, simuliertes `realloc`-Versagen, Erhalt früherer Zeilen, negative/ungültige/überlaufende Zahlen sowie gültige Hex-/`UINT64_MAX`-Werte geprüft. Apple-Typen waren Test-Doubles. |
| Nachgewiesen | `go mod verify` | Prüfsummenprüfung bestanden. |
| Nachgewiesen | `govulncheck@v1.9.0 -show verbose ./...` | Unter Go-1.27.3-Zielstdlib für Windows/amd64 (`CGO_ENABLED=1`), Linux/amd64 und Darwin/arm64 (jeweils `CGO_ENABLED=0`) keine bekannten Schwachstellen gefunden; auch keine zusätzlichen Package-/Module-Funde. |
| Beobachtet | CI-Workflow | Diff manuell geprüft; ein GitHub-CI-Lauf oder zusätzlicher Actionlint-Lauf wurde nicht durchgeführt. |

Die Scans verwendeten `https://vuln.go.dev` mit Datenbankstand **27. Oktober 2026, 21:16:18 UTC**. Der Scanner wurde außerhalb des Repositories installiert und abschließend auch mit Go 1.27.3 neu gebaut; `go version -m` und `govulncheck -version` bestätigten Versionen und Datenbankstand. Die CI verwendet dafür den reproduzierbaren Befehl `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`. Gegenüber dem ersten Scan unter Go 1.27.1 entfielen nach der Patchanhebung auch die ausschließlich auf Package-/Module-Ebene gemeldeten Standardbibliotheksbefunde; bereits im ersten Scan war kein betroffener Aufruf aus der Bibliothek erreichbar.

## Verbleibende Grenzen

- Native Linux- und macOS-Laufzeitprüfungen einschließlich echter procfs/sysfs-/FIFO-Zugriffe und Apple-Framework-/cgo-Integration sind auf diesem Windows-Rechner offen. Die vorhandene CI-Betriebssystemmatrix führt diese Tests nach einem Push aus; ein neuer CI-Lauf wurde hier nicht ausgelöst.
- Temporäre Windows-Harnesses prüfen nur übertragbare Go-Logik und extrahierte C-Helfer. Sie ersetzen keine Betriebssystemabnahme. Bestehende Linux-Fixtures lassen sich wegen PCI-Dateinamen mit Doppelpunkt und Windows-Symlinkrechten nicht vollständig unverändert unter Windows ausführen.
- Der Schwachstellenscan bewertet bekannte Go-Schwachstellen und erreichbare Go-Aufrufe; er prüft weder Apple-Frameworks noch WMI-/Kernelimplementierungen auf eigene Fehler.
- Die Pfadprüfungen sind keine Sandbox gegen gleichzeitige Änderungen durch privilegierte Prozesse. `O_NONBLOCK` und Leselimits begrenzen normale Spezialdatei- und Größenfälle; sie liefern keine globale Zeitgarantie für fehlerhafte Kernel-, Treiber- oder WMI-Aufrufe. Die bestehende synchrone API erhält keinen zusätzlichen Hintergrundworker oder Timeoutvertrag.
- Hardwaretexte bleiben untrusted Eingaben. Aufrufer müssen sie für HTML, Terminal, Protokolle oder andere Ausgaben passend behandeln und Inventar wegen enthaltener Gerätekennungen geschützt verarbeiten.
