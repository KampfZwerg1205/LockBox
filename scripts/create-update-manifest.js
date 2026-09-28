"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const distDirectory = path.join(root, "dist");
const packageInfo = require(path.join(root, "package.json"));

async function sha512(filePath) {
    const hash = crypto.createHash("sha512");

    for await (const chunk of fs.createReadStream(filePath)) {
        hash.update(chunk);
    }

    return hash.digest("base64");
}

async function main() {
    const installer = `LOCKBOX-Setup-${packageInfo.version}.exe`;

    if (!fs.existsSync(path.join(distDirectory, installer))) {
        throw new Error("Kein LOCKBOX-NSIS-Installer im Ordner dist gefunden.");
    }

    const installerPath = path.join(distDirectory, installer);
    const fileInfo = {
        url: installer,
        sha512: await sha512(installerPath),
        size: fs.statSync(installerPath).size
    };
    const manifest = {
        version: packageInfo.version,
        files: [fileInfo],
        path: fileInfo.url,
        sha512: fileInfo.sha512,
        releaseDate: new Date().toISOString()
    };

    fs.writeFileSync(
        path.join(distDirectory, "latest.yml"),
        `${JSON.stringify(manifest, null, 2)}\n`,
        "utf8"
    );

    console.log(`Update-Manifest für LOCKBOX ${packageInfo.version} erstellt.`);
}

main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
});
