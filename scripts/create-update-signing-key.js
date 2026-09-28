"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const appData = process.env.APPDATA || os.homedir();
const keyDirectory = path.join(appData, "LOCKBOX");
const keyPath = path.join(keyDirectory, "release-signing-key.pem");

fs.mkdirSync(keyDirectory, { recursive: true });

if (fs.existsSync(keyPath)) {
    throw new Error(`Ein Update-Signierschlüssel existiert bereits: ${keyPath}`);
}

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
fs.writeFileSync(
    keyPath,
    privateKey.export({ type: "pkcs8", format: "pem" }),
    { flag: "wx", mode: 0o600 }
);

console.log("Privater Update-Signierschlüssel gespeichert außerhalb des Projektordners.");
console.log("Öffentlicher Schlüssel für assets/update-public-key.pem:");
console.log(publicKey.export({ type: "spki", format: "pem" }).toString());
