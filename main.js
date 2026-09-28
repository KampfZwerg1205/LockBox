"use strict";

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const {
    app,
    BrowserWindow,
    clipboard,
    dialog,
    ipcMain,
    session
} = require("electron");
const { autoUpdater } = require("electron-updater");

const APP_ID = "com.lockbox.passwordmanager";
const UPDATE_OWNER = "KampfZwerg1205";
const UPDATE_REPOSITORY = "lockbox";
const UPDATE_PUBLIC_KEY = fs.readFileSync(
    path.join(__dirname, "assets", "update-public-key.pem")
);
const APP_PAGE = path.join(__dirname, "index.html");
const CLIPBOARD_CLEAR_DELAY_MS = 30 * 1000;
let mainWindow = null;
let verifiedUpdate = null;
let clipboardClearTimer = null;
let copiedClipboardText = null;

app.setAppUserModelId(APP_ID);
app.setName("LOCKBOX");

// Keep the desktop app's localStorage separate from browser data. This does
// not read, overwrite, or delete the existing browser vault.
app.setPath(
    "userData",
    path.join(app.getPath("appData"), "LOCKBOX")
);

function createWindow() {
    const window = new BrowserWindow({
        width: 1280,
        height: 850,
        minWidth: 360,
        minHeight: 600,
        show: false,
        autoHideMenuBar: true,
        backgroundColor: "#020617",
        title: "LOCKBOX",
        icon: path.join(__dirname, "assets", "lockbox.ico"),
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: true,
            webSecurity: true,
            allowRunningInsecureContent: false,
            devTools: false
        }
    });

    window.once("ready-to-show", () => window.show());

    window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    window.webContents.on("will-navigate", (event, targetUrl) => {
        let targetPath;

        try {
            targetPath = require("node:url").fileURLToPath(targetUrl);
        } catch {
            event.preventDefault();
            return;
        }

        if (path.resolve(targetPath) !== path.resolve(APP_PAGE)) {
            event.preventDefault();
        }
    });

    window.loadFile(APP_PAGE);
    mainWindow = window;

    window.on("closed", () => {
        if (mainWindow === window) mainWindow = null;
    });
}

function isTrustedAppFrame(frame) {
    if (!frame) return false;

    try {
        const framePath = require("node:url").fileURLToPath(frame.url);
        return path.resolve(framePath) === path.resolve(APP_PAGE);
    } catch {
        return false;
    }
}

function clearCopiedClipboardIfUnchanged() {
    if (clipboardClearTimer) {
        clearTimeout(clipboardClearTimer);
        clipboardClearTimer = null;
    }

    if (
        copiedClipboardText !== null &&
        clipboard.readText() === copiedClipboardText
    ) {
        clipboard.clear();
    }

    copiedClipboardText = null;
}

function configureClipboard() {
    ipcMain.handle("lockbox:copy-to-clipboard", (event, text) => {
        if (!isTrustedAppFrame(event.senderFrame)) {
            throw new Error("Clipboard access is limited to the LOCKBOX app.");
        }

        if (typeof text !== "string" || text.length > 100000) {
            throw new TypeError("Invalid clipboard text.");
        }

        if (clipboardClearTimer) {
            clearTimeout(clipboardClearTimer);
        }

        clipboard.writeText(text);
        copiedClipboardText = text;
        clipboardClearTimer = setTimeout(() => {
            if (
                copiedClipboardText === text &&
                clipboard.readText() === text
            ) {
                clipboard.clear();
            }

            if (copiedClipboardText === text) {
                copiedClipboardText = null;
                clipboardClearTimer = null;
            }
        }, CLIPBOARD_CLEAR_DELAY_MS);

        return true;
    });
}

function fileNameFromUpdateFile(file) {
    const value = String(file.url || file.name || "");

    try {
        return decodeURIComponent(
            path.posix.basename(new URL(value).pathname)
        );
    } catch {
        return path.posix.basename(value.replaceAll("\\", "/"));
    }
}

async function verifyPublishedUpdate(info) {
    const releaseBase =
        `https://github.com/${UPDATE_OWNER}/${UPDATE_REPOSITORY}/releases/latest/download`;
    const [manifestResponse, signatureResponse] = await Promise.all([
        fetch(`${releaseBase}/latest.yml`, {
            cache: "no-store",
            signal: AbortSignal.timeout(15000)
        }),
        fetch(`${releaseBase}/latest.yml.sig`, {
            cache: "no-store",
            signal: AbortSignal.timeout(15000)
        })
    ]);

    if (!manifestResponse.ok || !signatureResponse.ok) {
        throw new Error("The signed update manifest is missing.");
    }

    const manifestBytes = Buffer.from(
        await manifestResponse.arrayBuffer()
    );
    const signatureText = (await signatureResponse.text()).trim();
    const signature = Buffer.from(signatureText, "base64");

    if (
        !signature.length ||
        !crypto.verify(
            null,
            manifestBytes,
            UPDATE_PUBLIC_KEY,
            signature
        )
    ) {
        throw new Error("The update manifest signature is invalid.");
    }

    const manifest = JSON.parse(manifestBytes.toString("utf8"));
    if (manifest.version !== info.version || !Array.isArray(manifest.files)) {
        throw new Error("The signed manifest does not match the update.");
    }

    const offeredFiles = Array.isArray(info.files) ? info.files : [];
    const signedFile = manifest.files.find((candidate) =>
        offeredFiles.some((offered) =>
            candidate.sha512 === offered.sha512 &&
            candidate.url === fileNameFromUpdateFile(offered)
        )
    );

    if (!signedFile) {
        throw new Error("The installer checksum is not covered by the signature.");
    }

    return {
        version: manifest.version,
        sha512: signedFile.sha512
    };
}

function configureAutoUpdates() {
    if (!app.isPackaged) return;

    // The release manifest is authenticated with the app-pinned Ed25519 key
    // before downloading. The built-in Authenticode check is disabled because
    // this personal app is not distributed with a paid Windows certificate.
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.verifyUpdateCodeSignature = false;
    autoUpdater.allowPrerelease = false;

    autoUpdater.on("update-available", async (info) => {
        try {
            verifiedUpdate = await verifyPublishedUpdate(info);
            await autoUpdater.downloadUpdate();
        } catch (error) {
            verifiedUpdate = null;
            console.error("LOCKBOX update verification failed:", error);

            if (mainWindow) {
                await dialog.showMessageBox(mainWindow, {
                    type: "warning",
                    title: "LOCKBOX-Update abgebrochen",
                    message:
                        "Die neue Version konnte nicht sicher verifiziert werden. Das Update wurde nicht installiert.",
                    buttons: ["OK"],
                    noLink: true
                });
            }
        }
    });

    autoUpdater.on("update-downloaded", async () => {
        if (!verifiedUpdate) return;

        const result = await dialog.showMessageBox(mainWindow, {
            type: "info",
            title: "LOCKBOX-Update bereit",
            message: `LOCKBOX ${verifiedUpdate.version} ist heruntergeladen und geprüft.`,
            detail: "Das Update wird beim nächsten Neustart installiert.",
            buttons: ["Jetzt neu starten", "Später"],
            defaultId: 0,
            cancelId: 1,
            noLink: true
        });

        if (result.response === 0) {
            autoUpdater.quitAndInstall(false, true);
        } else {
            autoUpdater.autoInstallOnAppQuit = true;
        }
    });

    autoUpdater.on("error", (error) => {
        console.warn("LOCKBOX konnte nicht nach Updates suchen:", error);
    });

    setTimeout(() => {
        autoUpdater.checkForUpdates().catch((error) => {
            console.warn("LOCKBOX-Updateprüfung fehlgeschlagen:", error);
        });
    }, 5000);
}

app.whenReady().then(() => {
    configureClipboard();
    session.defaultSession.setPermissionRequestHandler(
        (_webContents, _permission, callback) => callback(false)
    );

    createWindow();
    configureAutoUpdates();

    app.on("activate", () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", clearCopiedClipboardIfUnchanged);
