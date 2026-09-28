"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const appData = process.env.APPDATA || os.homedir();
const defaultKeyPath = path.join(
    appData,
    "LOCKBOX",
    "release-signing-key.pem"
);
const keyPath = process.env.LOCKBOX_UPDATE_SIGNING_KEY || defaultKeyPath;
const publicKeyPath = path.join(root, "assets", "update-public-key.pem");
const manifestPath = path.join(root, "dist", "latest.yml");

if (!fs.existsSync(keyPath)) {
    throw new Error(
        "Update-Signierschlüssel fehlt. Starte zuerst npm run update:keygen."
    );
}

if (!fs.existsSync(manifestPath)) {
    throw new Error(
        "dist/latest.yml fehlt. Erstelle zuerst den Installer und das Manifest."
    );
}

const manifest = fs.readFileSync(manifestPath);
JSON.parse(manifest.toString("utf8"));
const privateKey = fs.readFileSync(keyPath);
const signatureBytes = crypto.sign(null, manifest, privateKey);
const publicKey = crypto.createPublicKey(privateKey);
const pinnedPublicKey = crypto.createPublicKey(
    fs.readFileSync(publicKeyPath)
);

if (
    !publicKey.export({ type: "spki", format: "der" }).equals(
        pinnedPublicKey.export({ type: "spki", format: "der" })
    )
) {
    throw new Error(
        "Der private Update-Schlüssel passt nicht zum öffentlichen Schlüssel der App."
    );
}

if (!crypto.verify(null, manifest, publicKey, signatureBytes)) {
    throw new Error("Die erzeugte Signatur konnte nicht geprüft werden.");
}

const signature = signatureBytes.toString("base64");

fs.writeFileSync(
    `${manifestPath}.sig`,
    `${signature}\n`,
    { encoding: "utf8", mode: 0o600 }
);

console.log("Update-Manifest mit dem lokalen Ed25519-Schlüssel signiert.");
