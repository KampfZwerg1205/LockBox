# LOCKBOX für Windows

LOCKBOX läuft als eigenständige Windows-App. Die App-Dateien sind lokal
gebündelt; der Vault wird mit AES-GCM verschlüsselt. PBKDF2 mit SHA-256 leitet
den Verschlüsselungsschlüssel aus dem Master-Passwort ab.

## Starten und installieren

1. Für die Entwicklung: Installiere [Node.js](https://nodejs.org/).
2. Öffne PowerShell in diesem Ordner und führe `npm ci` aus.
3. Starte die Entwicklungs-App mit `npm start`.
4. Erstelle den Windows-Installer mit `npm run dist`.

Der Installer liegt danach in `dist` und erstellt Verknüpfungen im Startmenü
und auf dem Desktop. Der portable Build ist mit `npm run dist:portable`
möglich; die automatische Updatefunktion ist für den installierten NSIS-Build
vorgesehen.

## Vault-Verschlüsselung und Migration

Der bestehende `lockbox_vault`-Schlüssel bleibt erhalten. Beim ersten Login mit
einem alten Vault werden die Klartextdaten mit dem bisherigen Master-Passwort
verschlüsselt und zurückgelesen. Erst nach erfolgreicher Prüfung wird der alte
Klartext-Master aus `lockbox_master` entfernt. Bei einem Fehler bleibt die
Migration gesperrt und vorhandene Daten werden nicht absichtlich gelöscht.

Neue Master-Passwörter müssen mindestens 12 Zeichen haben. Bestehende
Master-Passwörter werden bei der Migration nicht erzwungen geändert.

## Vorhandene Browser-Daten

Die Desktop-App hat einen eigenen lokalen Speicher. Ein zuvor im Browser
gespeicherter Vault bleibt dort unverändert und wird nicht automatisch in die
Desktop-App kopiert.

## Automatische Updates

Die installierte App prüft beim Start online auf eine neue GitHub-Release.
Wenn eine neue Version verfügbar ist, wird sie heruntergeladen und nach einer
Bestätigung beim Neustart installiert. Ein Update ersetzt die App-Dateien; der
Vault bleibt in `%APPDATA%\LOCKBOX`.

Jeder Release benötigt diese Dateien als Assets: den Windows-Installer, seine
`.blockmap`, `latest.yml` und `latest.yml.sig`. Für jede Version:

1. Erhöhe `version` in `package.json` und erstelle ein `v<version>`-Tag.
2. Erstelle mit `npm run dist` den Installer.
3. Erzeuge und signiere die Update-Metadaten mit `npm run update:manifest` und
   `npm run update:sign`.
4. Veröffentliche die vier Dateien in einer öffentlichen GitHub Release.

Den Ed25519-Update-Signierschlüssel erstellst du einmal mit
`npm run update:keygen`. Der private Schlüssel liegt außerhalb des Projekt-
und GitHub-Ordners unter `%APPDATA%\LOCKBOX\release-signing-key.pem`.
Bewahre eine sichere Sicherung davon auf. Ohne diesen Schlüssel können bereits
installierte Versionen keine neuen signierten Updates akzeptieren.

## Speicherort

Die Vault-Daten der Desktop-App liegen in `%APPDATA%\LOCKBOX`. Die
Deinstallation entfernt diesen Ordner nicht automatisch. Die Updateprüfung
benötigt eine Internetverbindung; der Vault selbst bleibt lokal.
