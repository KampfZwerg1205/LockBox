"use strict";

/* =========================================================
   LOCKBOX
   script.js
========================================================= */

const VAULT_KEY = "lockbox_vault";
const MASTER_KEY = "lockbox_master";
const ENCRYPTED_VAULT_FORMAT = "lockbox-encrypted-v1";
const BACKUP_FORMAT = "lockbox-backup-v1";
const PBKDF2_ITERATIONS = 600000;
const MAX_BACKUP_FILE_BYTES = 20 * 1024 * 1024;
const AUTO_LOCK_TIMEOUT_MS = 5 * 60 * 1000;

let vault = [];
let encryptionKey = null;
let vaultCryptoParams = null;
let saveQueue = Promise.resolve(true);
let pendingRestoreBackup = null;
let pendingRestoreValue = null;
let autoLockTimer = null;
let currentFilter = "all";
let editingId = null;
let currentDetailId = null;

/* =========================================================
   DOM
========================================================= */

const $ = (id) => document.getElementById(id);

const loginScreen = $("loginScreen");
const vaultScreen = $("vaultScreen");

const masterPassword = $("masterPassword");
const unlockButton = $("unlockButton");
const showCreateVaultButton = $("showCreateVaultButton");
const loginMessage = $("loginMessage");

const createVaultModal = $("createVaultModal");
const newMasterPassword = $("newMasterPassword");
const confirmMasterPassword = $("confirmMasterPassword");
const createVaultButton = $("createVaultButton");
const closeCreateVaultButton = $("closeCreateVaultButton");
const cancelCreateVaultButton = $("cancelCreateVaultButton");
const createVaultMessage = $("createVaultMessage");

const settingsButton = $("settingsButton");
const settingsModal = $("settingsModal");
const closeSettingsButton = $("closeSettingsButton");
const vaultBackupButton = $("vaultBackupButton");
const selectVaultBackupButton = $("selectVaultBackupButton");
const vaultBackupFileInput = $("vaultBackupFileInput");
const backupStatusMessage = $("backupStatusMessage");

const restoreBackupModal = $("restoreBackupModal");
const closeRestoreBackupButton = $("closeRestoreBackupButton");
const cancelRestoreBackupButton = $("cancelRestoreBackupButton");
const cancelRestoreBackupConfirmButton =
    $("cancelRestoreBackupConfirmButton");
const restoreBackupPassword = $("restoreBackupPassword");
const restoreBackupMessage = $("restoreBackupMessage");
const restoreBackupPasswordStep = $("restoreBackupPasswordStep");
const restoreBackupConfirmStep = $("restoreBackupConfirmStep");
const restoreBackupSummary = $("restoreBackupSummary");
const verifyRestoreBackupButton = $("verifyRestoreBackupButton");
const confirmRestoreBackupButton = $("confirmRestoreBackupButton");

const changeMasterPasswordButton = $("changeMasterPasswordButton");
const changeMasterPasswordModal = $("changeMasterPasswordModal");
const closeChangeMasterPasswordButton =
    $("closeChangeMasterPasswordButton");
const cancelChangeMasterPasswordButton =
    $("cancelChangeMasterPasswordButton");

const currentMasterPassword = $("currentMasterPassword");
const newMasterPasswordChange = $("newMasterPasswordChange");
const confirmMasterPasswordChange =
    $("confirmMasterPasswordChange");

const changeMasterPasswordSubmitButton =
    $("changeMasterPasswordSubmitButton");

const changeMasterPasswordMessage =
    $("changeMasterPasswordMessage");

const addButton = $("addButton");
const passwordModal = $("passwordModal");
const closeModalButton = $("closeModalButton");
const cancelButton = $("cancelButton");
const saveButton = $("saveButton");

const entryName = $("entryName");
const entryUsername = $("entryUsername");
const entryCategory = $("entryCategory");
const entryPassword = $("entryPassword");

const togglePasswordButton = $("togglePasswordButton");
const generatePasswordButton = $("generatePasswordButton");

const passwordMessage = $("passwordMessage");

const searchInput = $("searchInput");
const passwordList = $("passwordList");
const vaultSaveStatus = $("vaultSaveStatus");

const detailModal = $("detailModal");
const closeDetailButton = $("closeDetailButton");

const detailTitle = $("detailTitle");
const detailCategory = $("detailCategory");
const detailUsername = $("detailUsername");
const detailPassword = $("detailPassword");

const copyUsernameButton = $("copyUsernameButton");
const toggleDetailPasswordButton =
    $("toggleDetailPasswordButton");
const copyDetailPasswordButton =
    $("copyDetailPasswordButton");

const detailStrength = $("detailStrength");
const detailFavoriteButton = $("detailFavoriteButton");
const detailEditButton = $("detailEditButton");
const detailDeleteButton = $("detailDeleteButton");

const lockButton = $("lockButton");

const dashboardTotal = $("dashboardTotal");
const dashboardFavorites = $("dashboardFavorites");
const dashboardStrong = $("dashboardStrong");
const dashboardWeak = $("dashboardWeak");

const securityScore = $("securityScore");
const securityMessage = $("securityMessage");
const securityProgressFill = $("securityProgressFill");
const securityWarnings = $("securityWarnings");

const strengthFill = $("strengthFill");
const strengthText = $("strengthText");

const changeStrengthFill = $("changeStrengthFill");
const changeStrengthText = $("changeStrengthText");

const entryStrengthFill = $("entryStrengthFill");
const entryStrengthText = $("entryStrengthText");

/* =========================================================
   START
========================================================= */

document.addEventListener("DOMContentLoaded", () => {
    setupEvents();
    updateLoginState();
});

/* =========================================================
   LOCAL STORAGE
========================================================= */

function parseStoredVault(raw) {
    if (raw === null) return { type: "missing" };

    try {
        const value = JSON.parse(raw);

        if (Array.isArray(value)) {
            return { type: "legacy", value };
        }

        if (
            value &&
            value.format === ENCRYPTED_VAULT_FORMAT &&
            value.version === 1
        ) {
            return { type: "encrypted", value };
        }

        return { type: "invalid" };
    } catch {
        return { type: "invalid" };
    }
}

function bytesToBase64(bytes) {
    let binary = "";

    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
        binary += String.fromCharCode(
            ...bytes.subarray(offset, offset + 0x8000)
        );
    }

    return btoa(binary);
}

function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index++) {
        bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
}

async function deriveEncryptionKey(password, salt, iterations) {
    const passwordMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations,
            hash: "SHA-256"
        },
        passwordMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

function validateVaultEnvelope(envelope) {
    if (
        !envelope ||
        envelope.format !== ENCRYPTED_VAULT_FORMAT ||
        envelope.version !== 1 ||
        envelope.kdf !== "PBKDF2-SHA-256" ||
        envelope.cipher !== "AES-GCM-256" ||
        !Number.isInteger(envelope.iterations) ||
        envelope.iterations < 100000 ||
        envelope.iterations > 1000000 ||
        typeof envelope.salt !== "string" ||
        typeof envelope.iv !== "string" ||
        typeof envelope.ciphertext !== "string"
    ) {
        throw new Error("Ungültiges Vault-Format.");
    }

    const salt = base64ToBytes(envelope.salt);
    const iv = base64ToBytes(envelope.iv);
    const ciphertext = base64ToBytes(envelope.ciphertext);

    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
        throw new Error("Ungültige Verschlüsselungsdaten.");
    }

    return { salt, iv, ciphertext, iterations: envelope.iterations };
}

async function encryptWithKey(plaintext, key, cryptoParams) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        key,
        new TextEncoder().encode(plaintext)
    );

    return {
        format: ENCRYPTED_VAULT_FORMAT,
        version: 1,
        kdf: "PBKDF2-SHA-256",
        iterations: cryptoParams.iterations,
        salt: bytesToBase64(cryptoParams.salt),
        cipher: "AES-GCM-256",
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(new Uint8Array(encrypted))
    };
}

async function encryptVaultForPassword(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const cryptoParams = { salt, iterations: PBKDF2_ITERATIONS };
    const key = await deriveEncryptionKey(
        password,
        salt,
        cryptoParams.iterations
    );
    const envelope = await encryptWithKey(plaintext, key, cryptoParams);

    return { envelope, key, cryptoParams };
}

async function decryptVaultEnvelopeWithKey(envelope, key) {
    const params = validateVaultEnvelope(envelope);
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: params.iv, tagLength: 128 },
        key,
        params.ciphertext
    );
    const value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(plaintext)
    );

    if (!Array.isArray(value)) {
        throw new Error("Der entschlüsselte Vault hat ein ungültiges Format.");
    }

    return {
        value,
        cryptoParams: {
            salt: params.salt,
            iterations: params.iterations
        }
    };
}

async function decryptVaultEnvelope(envelope, password) {
    const params = validateVaultEnvelope(envelope);
    const key = await deriveEncryptionKey(
        password,
        params.salt,
        params.iterations
    );
    const decrypted = await decryptVaultEnvelopeWithKey(envelope, key);

    return { ...decrypted, key };
}

async function saveVault() {
    if (!encryptionKey || !vaultCryptoParams) {
        return false;
    }

    const key = encryptionKey;
    const cryptoParams = vaultCryptoParams;
    const plaintext = JSON.stringify(vault);

    vaultSaveStatus.textContent = "Änderungen werden verschlüsselt gespeichert …";
    vaultSaveStatus.classList.remove("saveError");

    saveQueue = saveQueue
        .catch(() => false)
        .then(async () => {
            const envelope = await encryptWithKey(
                plaintext,
                key,
                cryptoParams
            );

            localStorage.setItem(VAULT_KEY, JSON.stringify(envelope));
            vaultSaveStatus.textContent = "✅ Verschlüsselt gespeichert.";
            return true;
        })
        .catch((error) => {
            console.error("Vault konnte nicht gespeichert werden:", error);
            vaultSaveStatus.textContent =
                "❌ Speichern fehlgeschlagen. Deine letzte Änderung ist möglicherweise nicht gespeichert.";
            vaultSaveStatus.classList.add("saveError");
            return false;
        });

    return saveQueue;
}

/* =========================================================
   ENCRYPTED BACKUP AND RESTORE
========================================================= */

function isValidBackupVault(value) {
    return Array.isArray(value) && value.every((item) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
            return false;
        }

        const validId =
            typeof item.id === "string" ||
            (typeof item.id === "number" && Number.isFinite(item.id));
        const optionalText = (value) =>
            value === undefined || value === null || typeof value === "string";

        return validId &&
            optionalText(item.name) &&
            optionalText(item.password) &&
            optionalText(item.username) &&
            optionalText(item.category) &&
            (item.favorite === undefined || typeof item.favorite === "boolean") &&
            optionalText(item.createdAt) &&
            (item.strength === undefined ||
                ["strong", "medium", "weak"].includes(item.strength));
    });
}

function setBackupStatus(message, isError = false) {
    backupStatusMessage.textContent = message;
    backupStatusMessage.classList.toggle("saveError", isError);
}

async function downloadVaultBackup() {
    if (!encryptionKey || !vaultCryptoParams) return;

    vaultBackupButton.disabled = true;
    setBackupStatus("Verschlüsselte Sicherung wird erstellt …");

    try {
        await saveQueue.catch(() => false);

        const envelope = await encryptWithKey(
            JSON.stringify(vault),
            encryptionKey,
            vaultCryptoParams
        );
        const verified = await decryptVaultEnvelopeWithKey(
            envelope,
            encryptionKey
        );

        if (JSON.stringify(verified.value) !== JSON.stringify(vault)) {
            throw new Error("BACKUP_VERIFY_FAILED");
        }

        const backup = {
            format: BACKUP_FORMAT,
            version: 1,
            createdAt: new Date().toISOString(),
            vault: envelope
        };
        const blob = new Blob(
            [JSON.stringify(backup, null, 2)],
            { type: "application/json" }
        );
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        const timestamp = new Date()
            .toISOString()
            .replaceAll(":", "-")
            .replaceAll(".", "-");

        link.href = downloadUrl;
        link.download = `LOCKBOX-Sicherung-${timestamp}.json`;
        link.hidden = true;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);

        setBackupStatus(
            "✅ Verschlüsselte Sicherung heruntergeladen. Bewahre sie sicher auf."
        );
    } catch (error) {
        console.error("Verschlüsselte Sicherung fehlgeschlagen:", error);
        setBackupStatus("❌ Die Sicherung konnte nicht erstellt werden.", true);
    } finally {
        vaultBackupButton.disabled = false;
    }
}

async function selectVaultBackup(file) {
    if (!file) return;

    if (file.size > MAX_BACKUP_FILE_BYTES) {
        setBackupStatus("❌ Die Sicherungsdatei ist größer als 20 MB.", true);
        return;
    }

    try {
        const backup = JSON.parse(await file.text());

        if (
            !backup ||
            backup.format !== BACKUP_FORMAT ||
            backup.version !== 1 ||
            typeof backup.createdAt !== "string" ||
            !Number.isFinite(Date.parse(backup.createdAt))
        ) {
            throw new Error("INVALID_BACKUP");
        }

        validateVaultEnvelope(backup.vault);
        pendingRestoreBackup = backup;
        pendingRestoreValue = null;
        restoreBackupPassword.value = "";
        restoreBackupMessage.textContent = "";
        restoreBackupSummary.textContent = "";
        restoreBackupPasswordStep.classList.remove("hidden");
        restoreBackupConfirmStep.classList.add("hidden");
        settingsModal.classList.add("hidden");
        restoreBackupModal.classList.remove("hidden");
        restoreBackupPassword.focus();
    } catch (error) {
        console.warn("Sicherungsdatei konnte nicht gelesen werden:", error);
        setBackupStatus(
            "❌ Die Datei ist keine gültige LOCKBOX-Sicherung oder wurde beschädigt.",
            true
        );
    }
}

async function verifyVaultBackup() {
    if (!pendingRestoreBackup) return;

    const backupBeingVerified = pendingRestoreBackup;
    const password = restoreBackupPassword.value;
    if (!password) {
        restoreBackupMessage.textContent =
            "Bitte gib das Master-Passwort dieser Sicherung ein.";
        return;
    }

    verifyRestoreBackupButton.disabled = true;
    restoreBackupMessage.textContent = "Sicherung wird geprüft …";

    try {
        const restored = await decryptVaultEnvelope(
            backupBeingVerified.vault,
            password
        );

        if (
            pendingRestoreBackup !== backupBeingVerified ||
            restoreBackupModal.classList.contains("hidden")
        ) {
            return;
        }

        if (!isValidBackupVault(restored.value)) {
            throw new Error("INVALID_BACKUP_CONTENT");
        }

        pendingRestoreValue = restored.value;
        restoreBackupPassword.value = "";

        const createdAt = new Date(pendingRestoreBackup.createdAt);
        const formattedDate = new Intl.DateTimeFormat("de-DE", {
            dateStyle: "medium",
            timeStyle: "short"
        }).format(createdAt);

        restoreBackupSummary.textContent =
            `Die Sicherung ist gültig und enthält ${restored.value.length} ` +
            `${restored.value.length === 1 ? "Eintrag" : "Einträge"} ` +
            `(erstellt am ${formattedDate}).`;
        restoreBackupMessage.textContent = "";
        restoreBackupPasswordStep.classList.add("hidden");
        restoreBackupConfirmStep.classList.remove("hidden");
        confirmRestoreBackupButton.focus();
    } catch (error) {
        console.warn("Sicherungsdatei konnte nicht entschlüsselt werden:", error);
        restoreBackupPassword.value = "";
        restoreBackupMessage.textContent =
            error.name === "OperationError"
                ? "❌ Passwort falsch oder Sicherungsdatei beschädigt."
                : "❌ Die Sicherung enthält ungültige oder beschädigte Daten.";
        restoreBackupPassword.focus();
    } finally {
        verifyRestoreBackupButton.disabled = false;
    }
}

async function restoreVaultBackup() {
    if (
        !pendingRestoreValue ||
        !encryptionKey ||
        !vaultCryptoParams
    ) {
        return;
    }

    confirmRestoreBackupButton.disabled = true;

    const previousVault = vault;
    const previousEnvelope = localStorage.getItem(VAULT_KEY);
    let envelopeWasReplaced = false;
    let rollbackSucceeded = true;

    try {
        await saveQueue.catch(() => false);

        const replacementEnvelope = await encryptWithKey(
            JSON.stringify(pendingRestoreValue),
            encryptionKey,
            vaultCryptoParams
        );
        const prepared = await decryptVaultEnvelopeWithKey(
            replacementEnvelope,
            encryptionKey
        );

        if (
            JSON.stringify(prepared.value) !==
            JSON.stringify(pendingRestoreValue)
        ) {
            throw new Error("RESTORE_VERIFY_FAILED");
        }

        localStorage.setItem(
            VAULT_KEY,
            JSON.stringify(replacementEnvelope)
        );
        envelopeWasReplaced = true;

        const persisted = parseStoredVault(localStorage.getItem(VAULT_KEY));
        if (persisted.type !== "encrypted") {
            throw new Error("RESTORE_VERIFY_FAILED");
        }

        const checked = await decryptVaultEnvelopeWithKey(
            persisted.value,
            encryptionKey
        );
        if (JSON.stringify(checked.value) !== JSON.stringify(pendingRestoreValue)) {
            throw new Error("RESTORE_VERIFY_FAILED");
        }

        vault = checked.value;
        renderVault();
        closeRestoreBackupModal();
        setBackupStatus(
            "✅ Sicherung wiederhergestellt und mit deinem aktuellen Master-Passwort verschlüsselt."
        );
    } catch (error) {
        console.error("Sicherung konnte nicht wiederhergestellt werden:", error);
        vault = previousVault;

        if (envelopeWasReplaced && previousEnvelope !== null) {
            try {
                localStorage.setItem(VAULT_KEY, previousEnvelope);
            } catch (rollbackError) {
                rollbackSucceeded = false;
                console.error("Vorheriger Vault konnte nicht zurückgesetzt werden:", rollbackError);
            }
        }

        restoreBackupMessage.textContent =
            rollbackSucceeded
                ? "❌ Wiederherstellung fehlgeschlagen. Der bisherige Vault wurde beibehalten."
                : "❌ Wiederherstellung fehlgeschlagen. LOCKBOX konnte den vorherigen Speicherzustand nicht zurücksetzen. Lass die App geöffnet und sichere den Vault, bevor du sie schließt.";
        restoreBackupConfirmStep.classList.add("hidden");
        restoreBackupPasswordStep.classList.remove("hidden");
        restoreBackupPassword.focus();
    } finally {
        confirmRestoreBackupButton.disabled = false;
    }
}

function closeRestoreBackupModal(reopenSettings = true) {
    restoreBackupModal.classList.add("hidden");
    restoreBackupPassword.value = "";
    restoreBackupMessage.textContent = "";
    restoreBackupSummary.textContent = "";
    restoreBackupPasswordStep.classList.remove("hidden");
    restoreBackupConfirmStep.classList.add("hidden");
    pendingRestoreBackup = null;
    pendingRestoreValue = null;
    vaultBackupFileInput.value = "";

    if (reopenSettings && encryptionKey) {
        settingsModal.classList.remove("hidden");
    }
}

/* =========================================================
   LOGIN
========================================================= */

function updateLoginState() {
    const storedMaster = localStorage.getItem(MASTER_KEY);
    const storedVault = parseStoredVault(localStorage.getItem(VAULT_KEY));
    const hasStoredState = storedMaster !== null || storedVault.type !== "missing";

    loginScreen.classList.remove("hidden");
    vaultScreen.classList.add("hidden");
    showCreateVaultButton.classList.toggle("hidden", hasStoredState);

    if (storedVault.type === "invalid") {
        showMessage(
            loginMessage,
            "Vault-Daten sind vorhanden, aber das Format ist unbekannt. Sie wurden nicht verändert."
        );
    } else if (storedVault.type === "legacy" && !storedMaster) {
        showMessage(
            loginMessage,
            "Vorhandene Vault-Daten benötigen ihr bisheriges Master-Passwort. Sie wurden nicht verändert."
        );
    }
}

/* =========================================================
   UNLOCK
========================================================= */

async function unlockVault() {
    const enteredPassword = masterPassword.value;

    if (!enteredPassword) {

        showMessage(
            loginMessage,
            "Bitte gib dein Master-Passwort ein."
        );

        return;
    }

    unlockButton.disabled = true;

    try {
        const rawVault = localStorage.getItem(VAULT_KEY);
        const storedMaster = localStorage.getItem(MASTER_KEY);
        const storedVault = parseStoredVault(rawVault);
        let unlocked;

        if (storedVault.type === "encrypted") {
            unlocked = await decryptVaultEnvelope(
                storedVault.value,
                enteredPassword
            );

            // A previous interrupted migration may have left the old key behind.
            if (storedMaster !== null) {
                localStorage.removeItem(MASTER_KEY);
            }
        } else if (storedVault.type === "legacy" || storedVault.type === "missing") {
            if (!storedMaster) {
                showMessage(
                    loginMessage,
                    "Es wurde noch kein Vault erstellt."
                );
                showCreateVaultButton.classList.remove("hidden");
                return;
            }

            if (enteredPassword !== storedMaster) {
                throw new Error("WRONG_PASSWORD");
            }

            const legacyVault = storedVault.type === "legacy"
                ? storedVault.value
                : [];
            const plaintext = JSON.stringify(legacyVault);
            const prepared = await encryptVaultForPassword(
                plaintext,
                enteredPassword
            );
            const checked = await decryptVaultEnvelope(
                prepared.envelope,
                enteredPassword
            );

            if (JSON.stringify(checked.value) !== plaintext) {
                throw new Error("MIGRATION_VERIFY_FAILED");
            }

            // setItem is atomic. The legacy master key is removed only after
            // the encrypted payload has been written and read back successfully.
            localStorage.setItem(
                VAULT_KEY,
                JSON.stringify(prepared.envelope)
            );
            const persisted = parseStoredVault(
                localStorage.getItem(VAULT_KEY)
            );
            if (persisted.type !== "encrypted") {
                throw new Error("MIGRATION_VERIFY_FAILED");
            }

            unlocked = await decryptVaultEnvelope(
                persisted.value,
                enteredPassword
            );
            localStorage.removeItem(MASTER_KEY);
            vaultSaveStatus.textContent =
                "✅ Dein bisheriger Vault wurde verschlüsselt übernommen.";
        } else {
            throw new Error("INVALID_VAULT");
        }

        encryptionKey = unlocked.key;
        vaultCryptoParams = unlocked.cryptoParams;
        vault = unlocked.value;
        loginMessage.textContent = "";
        masterPassword.value = "";
        loginScreen.classList.add("hidden");
        vaultScreen.classList.remove("hidden");
        resetAutoLockTimer();
        renderVault();
    } catch (error) {
        console.error("Vault konnte nicht entsperrt werden:", error);
        masterPassword.select();

        if (error.message === "WRONG_PASSWORD" || error.name === "OperationError") {
            showMessage(
                loginMessage,
                "❌ Master-Passwort falsch oder Vault-Daten beschädigt."
            );
        } else if (error.message === "INVALID_VAULT") {
            showMessage(
                loginMessage,
                "Vault-Daten sind vorhanden, aber das Format ist unbekannt. Sie wurden nicht verändert."
            );
        } else {
            showMessage(
                loginMessage,
                "Vault konnte nicht sicher geöffnet werden. Die gespeicherten Daten wurden nicht absichtlich gelöscht."
            );
        }
    } finally {
        unlockButton.disabled = false;
    }
}

/* =========================================================
   CREATE VAULT
========================================================= */

function openCreateVaultModal() {

    newMasterPassword.value = "";
    confirmMasterPassword.value = "";

    createVaultMessage.textContent = "";

    updatePasswordStrength(
        "",
        strengthFill,
        strengthText
    );

    createVaultModal.classList.remove("hidden");
}

function closeCreateVaultModal() {
    createVaultModal.classList.add("hidden");
    newMasterPassword.value = "";
    confirmMasterPassword.value = "";
}

async function createVault() {

    const password = newMasterPassword.value;
    const confirm = confirmMasterPassword.value;

    if (!password) {

        showMessage(
            createVaultMessage,
            "Bitte erstelle ein Master-Passwort."
        );

        return;
    }

    if (password.length < 12) {

        showMessage(
            createVaultMessage,
            "Das Master-Passwort muss mindestens 12 Zeichen haben."
        );

        return;
    }

    if (password !== confirm) {

        showMessage(
            createVaultMessage,
            "Die Passwörter stimmen nicht überein."
        );

        return;
    }

    if (
        localStorage.getItem(VAULT_KEY) !== null ||
        localStorage.getItem(MASTER_KEY) !== null
    ) {
        showMessage(
            createVaultMessage,
            "Es sind bereits Vault-Daten vorhanden. Sie werden nicht überschrieben."
        );
        updateLoginState();
        return;
    }

    createVaultButton.disabled = true;

    try {
        const prepared = await encryptVaultForPassword("[]", password);
        const checked = await decryptVaultEnvelope(
            prepared.envelope,
            password
        );

        if (checked.value.length !== 0) {
            throw new Error("Vault-Prüfung fehlgeschlagen.");
        }

        localStorage.setItem(
            VAULT_KEY,
            JSON.stringify(prepared.envelope)
        );

        encryptionKey = null;
        vaultCryptoParams = null;
        vault = [];
        closeCreateVaultModal();
        loginMessage.textContent =
            "Verschlüsseltes Vault erstellt. Du kannst dich jetzt anmelden.";
        masterPassword.value = "";
        updateLoginState();
    } catch (error) {
        console.error("Vault konnte nicht erstellt werden:", error);
        showMessage(
            createVaultMessage,
            "Vault konnte nicht sicher erstellt werden. Es wurden keine vorhandenen Daten überschrieben."
        );
    } finally {
        createVaultButton.disabled = false;
    }
}

/* =========================================================
   LOCK
========================================================= */

async function lockVault() {
    if (autoLockTimer) {
        clearTimeout(autoLockTimer);
        autoLockTimer = null;
    }

    await saveQueue.catch(() => false);

    encryptionKey = null;
    vaultCryptoParams = null;
    vault = [];

    vaultScreen.classList.add("hidden");
    loginScreen.classList.remove("hidden");

    masterPassword.value = "";
    loginMessage.textContent = "";
    entryPassword.value = "";
    entryName.value = "";
    entryUsername.value = "";
    detailPassword.value = "";
    detailUsername.textContent = "";
    detailTitle.textContent = "🔐 Passwort";
    currentMasterPassword.value = "";
    newMasterPasswordChange.value = "";
    confirmMasterPasswordChange.value = "";

    currentDetailId = null;

    closeAllModals();
    passwordList.replaceChildren();
    updateLoginState();
}

function resetAutoLockTimer() {
    if (autoLockTimer) {
        clearTimeout(autoLockTimer);
        autoLockTimer = null;
    }

    if (!encryptionKey || vaultScreen.classList.contains("hidden")) {
        return;
    }

    autoLockTimer = setTimeout(() => {
        autoLockTimer = null;
        void lockVault();
    }, AUTO_LOCK_TIMEOUT_MS);
}

/* =========================================================
   MASTER PASSWORD CHANGE
========================================================= */

function openChangeMasterPasswordModal() {

    currentMasterPassword.value = "";
    newMasterPasswordChange.value = "";
    confirmMasterPasswordChange.value = "";

    changeMasterPasswordMessage.textContent = "";

    updatePasswordStrength(
        "",
        changeStrengthFill,
        changeStrengthText
    );

    settingsModal.classList.add("hidden");
    changeMasterPasswordModal.classList.remove("hidden");
}

function closeChangeMasterPasswordModal() {
    changeMasterPasswordModal.classList.add("hidden");
    currentMasterPassword.value = "";
    newMasterPasswordChange.value = "";
    confirmMasterPasswordChange.value = "";
}

async function changeMasterPassword() {

    const current = currentMasterPassword.value;
    const newPassword = newMasterPasswordChange.value;
    const confirm = confirmMasterPasswordChange.value;

    if (!current) {
        showMessage(
            changeMasterPasswordMessage,
            "Bitte gib dein aktuelles Master-Passwort ein."
        );
        return;
    }

    if (!newPassword) {

        showMessage(
            changeMasterPasswordMessage,
            "Bitte gib ein neues Master-Passwort ein."
        );

        return;
    }

    if (newPassword.length < 12) {

        showMessage(
            changeMasterPasswordMessage,
            "Das neue Master-Passwort muss mindestens 12 Zeichen haben."
        );

        return;
    }

    if (newPassword !== confirm) {

        showMessage(
            changeMasterPasswordMessage,
            "Die neuen Passwörter stimmen nicht überein."
        );

        return;
    }

    changeMasterPasswordSubmitButton.disabled = true;

    try {
        const pendingSaveSucceeded = await saveQueue;
        if (!pendingSaveSucceeded) {
            throw new Error("VAULT_SAVE_FAILED");
        }

        const stored = parseStoredVault(localStorage.getItem(VAULT_KEY));

        if (stored.type !== "encrypted") {
            throw new Error("VAULT_NOT_ENCRYPTED");
        }

        // Decrypting with the entered current password verifies it without
        // keeping the master password in localStorage or application state.
        await decryptVaultEnvelope(stored.value, current);

        const plaintext = JSON.stringify(vault);
        const prepared = await encryptVaultForPassword(
            plaintext,
            newPassword
        );
        const checked = await decryptVaultEnvelope(
            prepared.envelope,
            newPassword
        );

        if (JSON.stringify(checked.value) !== plaintext) {
            throw new Error("PASSWORD_CHANGE_VERIFY_FAILED");
        }

        localStorage.setItem(
            VAULT_KEY,
            JSON.stringify(prepared.envelope)
        );

        encryptionKey = prepared.key;
        vaultCryptoParams = prepared.cryptoParams;
        try {
            localStorage.removeItem(MASTER_KEY);
        } catch (cleanupError) {
            console.warn("Altes Master-Passwort konnte nicht entfernt werden:", cleanupError);
        }

        changeMasterPasswordMessage.textContent =
            "✅ Master-Passwort erfolgreich geändert.";

        currentMasterPassword.value = "";
        newMasterPasswordChange.value = "";
        confirmMasterPasswordChange.value = "";

        setTimeout(() => {
            closeChangeMasterPasswordModal();
        }, 800);
    } catch (error) {
        console.error("Master-Passwort konnte nicht geändert werden:", error);

        showMessage(
            changeMasterPasswordMessage,
            error.name === "OperationError"
                ? "❌ Das aktuelle Master-Passwort ist falsch."
                : "Das Master-Passwort konnte nicht geändert werden. Dein bisheriger Vault bleibt erhalten."
        );
    } finally {
        changeMasterPasswordSubmitButton.disabled = false;
    }
}

/* =========================================================
   PASSWORD MODAL
========================================================= */

function openAddPasswordModal() {

    editingId = null;

    $("passwordModalTitle").textContent =
        "Passwort hinzufügen";

    entryName.value = "";
    entryUsername.value = "";
    entryCategory.value = "Social";
    entryPassword.value = "";

    passwordMessage.textContent = "";

    updatePasswordStrength(
        "",
        entryStrengthFill,
        entryStrengthText
    );

    passwordModal.classList.remove("hidden");
}

function openEditPasswordModal(id) {

    const item = vault.find(
        (entry) => String(entry.id) === String(id)
    );

    if (!item) return;

    editingId = item.id;

    $("passwordModalTitle").textContent =
        "Passwort bearbeiten";

    entryName.value = item.name || "";
    entryUsername.value = item.username || "";
    entryCategory.value = item.category || "Sonstiges";
    entryPassword.value = item.password || "";

    passwordMessage.textContent = "";

    updatePasswordStrength(
        item.password || "",
        entryStrengthFill,
        entryStrengthText
    );

    closeDetailModal();

    passwordModal.classList.remove("hidden");
}

function closePasswordModal() {
    passwordModal.classList.add("hidden");
    entryPassword.value = "";
    editingId = null;
}

/* =========================================================
   SAVE PASSWORD
========================================================= */

async function savePassword() {

    const name = entryName.value.trim();
    const username = entryUsername.value.trim();
    const category = entryCategory.value;
    const password = entryPassword.value;

    if (!name) {

        showMessage(
            passwordMessage,
            "Bitte gib einen Namen ein."
        );

        return;
    }

    if (!password) {

        showMessage(
            passwordMessage,
            "Bitte gib ein Passwort ein."
        );

        return;
    }

    const previousVault = JSON.stringify(vault);
    const strength = getPasswordStrength(password);

    if (editingId !== null) {

        const item = vault.find(
            (entry) => String(entry.id) === String(editingId)
        );

        if (item) {

            item.name = name;
            item.username = username;
            item.category = category;
            item.password = password;
            item.strength = strength.level;
        }

    } else {

        vault.push({
            id: Date.now().toString(),
            name,
            username,
            category,
            password,
            favorite: false,
            strength: strength.level,
            createdAt: new Date().toISOString()
        });
    }

    const saved = await saveVault();

    if (!saved) {
        vault = JSON.parse(previousVault);
        showMessage(
            passwordMessage,
            "Speichern fehlgeschlagen. Bitte prüfe den verfügbaren Speicherplatz und versuche es erneut."
        );
        renderVault();
        return;
    }

    renderVault();

    closePasswordModal();
}

/* =========================================================
   PASSWORD GENERATOR
========================================================= */

function generatePassword() {

    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
        "abcdefghijklmnopqrstuvwxyz" +
        "0123456789" +
        "!@#$%^&*()-_=+[]{}";

    let password = "";
    const range = 0x100000000;
    const maxAccepted = Math.floor(range / characters.length) * characters.length;

    for (let i = 0; i < 20; i++) {
        let value;

        do {
            const random = crypto.getRandomValues(new Uint32Array(1))[0];
            value = random;
        } while (value >= maxAccepted);

        password += characters[value % characters.length];
    }

    entryPassword.value = password;

    updatePasswordStrength(
        password,
        entryStrengthFill,
        entryStrengthText
    );
}

/* =========================================================
   PASSWORD STRENGTH
========================================================= */

function getPasswordStrength(password) {

    if (!password) {

        return {
            level: "weak",
            text: "Keine Bewertung",
            score: 0
        };
    }

    let score = 0;

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score >= 5) {

        return {
            level: "strong",
            text: "Stark",
            score: 100
        };

    }

    if (score >= 3) {

        return {
            level: "medium",
            text: "Mittel",
            score: 60
        };
    }

    return {
        level: "weak",
        text: "Schwach",
        score: 25
    };
}

function updatePasswordStrength(
    password,
    fill,
    textElement
) {

    if (!fill || !textElement) return;

    const result = getPasswordStrength(password);

    fill.style.width = `${result.score}%`;

    textElement.textContent =
        result.text;
}

/* =========================================================
   RENDER VAULT
========================================================= */

function renderVault() {

    updateDashboard();
    updateSecurity();

    const search =
        searchInput.value
            .trim()
            .toLowerCase();

    let filtered = [...vault];

    /* Filter */

    if (currentFilter === "strong") {

        filtered = filtered.filter(
            (item) =>
                getEntryStrength(item) === "strong"
        );

    } else if (currentFilter === "medium") {

        filtered = filtered.filter(
            (item) =>
                getEntryStrength(item) === "medium"
        );

    } else if (currentFilter === "weak") {

        filtered = filtered.filter(
            (item) =>
                getEntryStrength(item) === "weak"
        );

    } else if (currentFilter === "favorite") {

        filtered = filtered.filter(
            (item) => item.favorite === true
        );
    }

    /* Search */

    if (search) {

        filtered = filtered.filter((item) => {

            return (
                String(item.name || "")
                    .toLowerCase()
                    .includes(search) ||

                String(item.username || "")
                    .toLowerCase()
                    .includes(search) ||

                String(item.category || "")
                    .toLowerCase()
                    .includes(search)
            );
        });
    }

    if (filtered.length === 0) {

        passwordList.innerHTML = `
            <div class="emptyState">
                <div class="emptyStateIcon">🔐</div>

                <h3>
                    Keine Passwörter gefunden
                </h3>

                <p>
                    ${
                        vault.length === 0
                            ? "Füge dein erstes Passwort hinzu."
                            : "Ändere deine Suche oder den Filter."
                    }
                </p>
            </div>
        `;

        return;
    }

    passwordList.innerHTML =
        filtered
            .map(createPasswordCard)
            .join("");

    setupCardEvents();
}

/* =========================================================
   PASSWORD CARD
========================================================= */

function createPasswordCard(item) {

    const strength =
        getEntryStrength(item);

    const strengthText =
        strength === "strong"
            ? "Stark"
            : strength === "medium"
                ? "Mittel"
                : "Schwach";

    const favorite =
        item.favorite === true;

    const favoriteText =
        favorite
            ? "⭐ Favorit"
            : "☆ Favorit";

    return `
        <article
            class="passwordCard"
            data-id="${escapeHtml(item.id)}"
        >

            <div class="passwordCardInfo">

                <div class="passwordCardTitle">

                    ${
                        favorite
                            ? "⭐"
                            : "🔐"
                    }

                    <span>
                        ${escapeHtml(item.name || "Ohne Namen")}
                    </span>

                </div>

                ${
                    item.username
                        ? `
                            <div class="passwordCardUsername">
                                ${escapeHtml(item.username)}
                            </div>
                        `
                        : ""
                }

                <span class="passwordCardCategory">
                    ${escapeHtml(item.category || "Sonstiges")}
                </span>

                <div>
                    <span
                        class="passwordCardStrength ${strength}"
                    >
                        ${
                            strength === "strong"
                                ? "🟢"
                                : strength === "medium"
                                    ? "🟡"
                                    : "🔴"
                        }

                        ${strengthText}
                    </span>
                </div>

            </div>


            <div class="passwordCardActions">

                <button
                    type="button"
                    class="cardActionButton favorite ${
                        favorite ? "active" : ""
                    }"
                    data-action="favorite"
                    data-id="${escapeHtml(item.id)}"
                >
                    ${favoriteText}
                </button>


                <button
                    type="button"
                    class="cardActionButton"
                    data-action="copy"
                    data-id="${escapeHtml(item.id)}"
                >
                    📋 Kopieren
                </button>


                <button
                    type="button"
                    class="cardActionButton"
                    data-action="view"
                    data-id="${escapeHtml(item.id)}"
                >
                    👁️ Anzeigen
                </button>


                <button
                    type="button"
                    class="cardActionButton"
                    data-action="edit"
                    data-id="${escapeHtml(item.id)}"
                >
                    ✏️ Bearbeiten
                </button>


                <button
                    type="button"
                    class="cardActionButton delete"
                    data-action="delete"
                    data-id="${escapeHtml(item.id)}"
                >
                    🗑️ Löschen
                </button>

            </div>

        </article>
    `;
}

/* =========================================================
   CARD EVENTS
========================================================= */

function setupCardEvents() {

    document
        .querySelectorAll(".cardActionButton")
        .forEach((button) => {

            button.addEventListener(
                "click",
                (event) => {

                    event.stopPropagation();

                    const id =
                        button.dataset.id;

                    const action =
                        button.dataset.action;

                    handleCardAction(
                        action,
                        id
                    );
                }
            );
        });


    document
        .querySelectorAll(".passwordCard")
        .forEach((card) => {

            card.addEventListener(
                "click",
                () => {

                    openDetailModal(
                        card.dataset.id
                    );
                }
            );
        });
}

/* =========================================================
   CARD ACTIONS
========================================================= */

async function handleCardAction(action, id) {

    const item = vault.find(
        (entry) =>
            String(entry.id) === String(id)
    );

    if (!item) return;

    if (action === "favorite") {
        const wasFavorite = item.favorite === true;
        item.favorite =
            !item.favorite;

        const saved = await saveVault();

        if (!saved) {
            item.favorite = wasFavorite;
        }

        renderVault();

        if (
            currentDetailId &&
            String(currentDetailId) === String(id)
        ) {
            updateDetailFavoriteButton(item);
        }

        return;
    }

    if (action === "copy") {

        copyToClipboard(
            item.password || ""
        );

        return;
    }

    if (action === "view") {

        openDetailModal(id);

        return;
    }

    if (action === "edit") {

        openEditPasswordModal(id);

        return;
    }

    if (action === "delete") {

        deletePassword(id);
    }
}

/* =========================================================
   DETAIL MODAL
========================================================= */

function openDetailModal(id) {

    const item = vault.find(
        (entry) =>
            String(entry.id) === String(id)
    );

    if (!item) return;

    currentDetailId = item.id;

    detailTitle.textContent =
        `${item.favorite ? "⭐" : "🔐"} ${item.name || "Passwort"}`;

    detailCategory.textContent =
        item.category || "Sonstiges";

    detailUsername.textContent =
        item.username || "-";

    detailPassword.value =
        item.password || "";

    detailPassword.type = "password";

    toggleDetailPasswordButton.textContent =
        "👁️";

    const strength =
        getEntryStrength(item);

    detailStrength.textContent =
        strength === "strong"
            ? "🟢 Stark"
            : strength === "medium"
                ? "🟡 Mittel"
                : "🔴 Schwach";

    updateDetailFavoriteButton(item);

    detailModal.classList.remove("hidden");
}

function closeDetailModal() {

    detailModal.classList.add("hidden");
    detailPassword.value = "";
    detailPassword.type = "password";

    currentDetailId = null;
}

function updateDetailFavoriteButton(item) {

    if (!item) return;

    if (item.favorite) {

        detailFavoriteButton.textContent =
            "⭐ Favorit";

        detailFavoriteButton.classList.add(
            "active"
        );

    } else {

        detailFavoriteButton.textContent =
            "☆ Favorit";

        detailFavoriteButton.classList.remove(
            "active"
        );
    }
}

/* =========================================================
   DELETE
========================================================= */

async function deletePassword(id) {

    const item = vault.find(
        (entry) =>
            String(entry.id) === String(id)
    );

    if (!item) return;

    const confirmed =
        confirm(
            `Möchtest du "${item.name}" wirklich löschen?`
        );

    if (!confirmed) return;

    const previousVault = vault;
    vault =
        vault.filter(
            (entry) =>
                String(entry.id) !== String(id)
        );

    const saved = await saveVault();

    if (!saved) {
        vault = previousVault;
        vaultSaveStatus.textContent =
            "❌ Löschen wurde nicht gespeichert. Der Eintrag wurde wiederhergestellt.";
        vaultSaveStatus.classList.add("saveError");
        renderVault();
        return;
    }

    closeDetailModal();

    renderVault();
}

/* =========================================================
   DASHBOARD
========================================================= */

function updateDashboard() {

    const total =
        vault.length;

    const favorites =
        vault.filter(
            (item) => item.favorite === true
        ).length;

    const strong =
        vault.filter(
            (item) =>
                getEntryStrength(item) === "strong"
        ).length;

    const weak =
        vault.filter(
            (item) =>
                getEntryStrength(item) === "weak"
        ).length;

    dashboardTotal.textContent =
        total;

    dashboardFavorites.textContent =
        favorites;

    dashboardStrong.textContent =
        strong;

    dashboardWeak.textContent =
        weak;
}

/* =========================================================
   SECURITY
========================================================= */

function updateSecurity() {

    if (vault.length === 0) {

        securityScore.textContent = "0%";

        securityProgressFill.style.width =
            "0%";

        securityMessage.textContent =
            "Noch keine Passwörter vorhanden.";

        securityWarnings.innerHTML = "";

        return;
    }

    let score = 0;

    const strong =
        vault.filter(
            (item) =>
                getEntryStrength(item) === "strong"
        ).length;

    const medium =
        vault.filter(
            (item) =>
                getEntryStrength(item) === "medium"
        ).length;

    const weak =
        vault.filter(
            (item) =>
                getEntryStrength(item) === "weak"
        ).length;

    score =
        Math.round(
            (
                strong * 100 +
                medium * 60 +
                weak * 25
            ) / vault.length
        );

    securityScore.textContent =
        `${score}%`;

    securityProgressFill.style.width =
        `${score}%`;

    if (score >= 80) {

        securityMessage.textContent =
            "Dein Vault ist gut geschützt.";

    } else if (score >= 60) {

        securityMessage.textContent =
            "Dein Vault ist teilweise geschützt.";

    } else {

        securityMessage.textContent =
            "Einige Passwörter sollten verbessert werden.";
    }

    const warnings = [];

    if (weak > 0) {

        warnings.push(
            `🔴 ${weak} schwaches Passwort`
        );
    }

    if (medium > 0) {

        warnings.push(
            `🟡 ${medium} mittleres Passwort`
        );
    }

    if (warnings.length === 0) {

        securityWarnings.innerHTML =
            "✅ Keine kritischen Passwortprobleme gefunden.";

    } else {

        securityWarnings.innerHTML =
            warnings.join(" · ");
    }
}

/* =========================================================
   ENTRY STRENGTH
========================================================= */

function getEntryStrength(item) {

    if (item.strength === "strong") {
        return "strong";
    }

    if (item.strength === "medium") {
        return "medium";
    }

    if (item.strength === "weak") {
        return "weak";
    }

    return getPasswordStrength(
        item.password || ""
    ).level;
}

/* =========================================================
   COPY
========================================================= */

async function copyToClipboard(text) {

    if (!text) return;

    try {
        await window.lockboxClipboard.copy(text);
    } catch (error) {
        console.error("Zwischenablage konnte nicht aktualisiert werden:", error);
    }
}

/* =========================================================
   EVENTS
========================================================= */

function setupEvents() {

    ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"].forEach(
        (eventName) => {
            document.addEventListener(eventName, resetAutoLockTimer, {
                passive: true
            });
        }
    );

    /* Login */

    unlockButton.addEventListener(
        "click",
        unlockVault
    );

    masterPassword.addEventListener(
        "keydown",
        (event) => {

            if (event.key === "Enter") {
                unlockVault();
            }
        }
    );


    /* Create Vault */

    showCreateVaultButton.addEventListener(
        "click",
        openCreateVaultModal
    );

    createVaultButton.addEventListener(
        "click",
        createVault
    );

    closeCreateVaultButton.addEventListener(
        "click",
        closeCreateVaultModal
    );

    cancelCreateVaultButton.addEventListener(
        "click",
        closeCreateVaultModal
    );


    /* Password strength */

    newMasterPassword.addEventListener(
        "input",
        () => {

            updatePasswordStrength(
                newMasterPassword.value,
                strengthFill,
                strengthText
            );
        }
    );

    newMasterPasswordChange.addEventListener(
        "input",
        () => {

            updatePasswordStrength(
                newMasterPasswordChange.value,
                changeStrengthFill,
                changeStrengthText
            );
        }
    );

    entryPassword.addEventListener(
        "input",
        () => {

            updatePasswordStrength(
                entryPassword.value,
                entryStrengthFill,
                entryStrengthText
            );
        }
    );


    /* Settings */

    settingsButton.addEventListener(
        "click",
        () => {
            settingsModal.classList.remove("hidden");
        }
    );

    closeSettingsButton.addEventListener(
        "click",
        () => {
            settingsModal.classList.add("hidden");
        }
    );

    vaultBackupButton.addEventListener(
        "click",
        downloadVaultBackup
    );

    selectVaultBackupButton.addEventListener(
        "click",
        () => vaultBackupFileInput.click()
    );

    vaultBackupFileInput.addEventListener(
        "change",
        async () => {
            await selectVaultBackup(vaultBackupFileInput.files[0]);
            vaultBackupFileInput.value = "";
        }
    );

    closeRestoreBackupButton.addEventListener(
        "click",
        () => closeRestoreBackupModal()
    );

    cancelRestoreBackupButton.addEventListener(
        "click",
        () => closeRestoreBackupModal()
    );

    cancelRestoreBackupConfirmButton.addEventListener(
        "click",
        () => closeRestoreBackupModal()
    );

    verifyRestoreBackupButton.addEventListener(
        "click",
        verifyVaultBackup
    );

    restoreBackupPassword.addEventListener(
        "keydown",
        (event) => {
            if (event.key === "Enter") {
                verifyVaultBackup();
            }
        }
    );

    confirmRestoreBackupButton.addEventListener(
        "click",
        restoreVaultBackup
    );

    changeMasterPasswordButton.addEventListener(
        "click",
        openChangeMasterPasswordModal
    );


    /* Change Master Password */

    closeChangeMasterPasswordButton.addEventListener(
        "click",
        closeChangeMasterPasswordModal
    );

    cancelChangeMasterPasswordButton.addEventListener(
        "click",
        closeChangeMasterPasswordModal
    );

    changeMasterPasswordSubmitButton.addEventListener(
        "click",
        changeMasterPassword
    );


    /* Password */

    addButton.addEventListener(
        "click",
        openAddPasswordModal
    );

    closeModalButton.addEventListener(
        "click",
        closePasswordModal
    );

    cancelButton.addEventListener(
        "click",
        closePasswordModal
    );

    saveButton.addEventListener(
        "click",
        savePassword
    );

    generatePasswordButton.addEventListener(
        "click",
        generatePassword
    );


    /* Password visibility */

    togglePasswordButton.addEventListener(
        "click",
        () => {

            if (
                entryPassword.type === "password"
            ) {

                entryPassword.type = "text";

                togglePasswordButton.textContent =
                    "🙈";

            } else {

                entryPassword.type = "password";

                togglePasswordButton.textContent =
                    "👁️";
            }
        }
    );


    /* Search */

    searchInput.addEventListener(
        "input",
        renderVault
    );


    /* Filters */

    document
        .querySelectorAll(".filterButton")
        .forEach((button) => {

            button.addEventListener(
                "click",
                () => {

                    document
                        .querySelectorAll(
                            ".filterButton"
                        )
                        .forEach((btn) => {

                            btn.classList.remove(
                                "active"
                            );
                        });

                    button.classList.add(
                        "active"
                    );

                    currentFilter =
                        button.dataset.filter;

                    renderVault();
                }
            );
        });


    /* Detail */

    closeDetailButton.addEventListener(
        "click",
        closeDetailModal
    );

    detailFavoriteButton.addEventListener(
        "click",
        async () => {

            if (!currentDetailId) return;

            const item =
                vault.find(
                    (entry) =>
                        String(entry.id) ===
                        String(currentDetailId)
                );

            if (!item) return;

            const wasFavorite = item.favorite === true;
            item.favorite = !item.favorite;
            const saved = await saveVault();

            if (!saved) {
                item.favorite = wasFavorite;
            }

            updateDetailFavoriteButton(
                item
            );

            renderVault();
        }
    );

    detailEditButton.addEventListener(
        "click",
        () => {

            if (currentDetailId) {

                openEditPasswordModal(
                    currentDetailId
                );
            }
        }
    );

    detailDeleteButton.addEventListener(
        "click",
        () => {

            if (currentDetailId) {

                deletePassword(
                    currentDetailId
                );
            }
        }
    );


    /* Detail copy */

    copyUsernameButton.addEventListener(
        "click",
        () => {

            copyToClipboard(
                detailUsername.textContent
            );
        }
    );

    copyDetailPasswordButton.addEventListener(
        "click",
        () => {

            copyToClipboard(
                detailPassword.value
            );
        }
    );


    /* Detail password */

    toggleDetailPasswordButton.addEventListener(
        "click",
        () => {

            if (
                detailPassword.type === "password"
            ) {

                detailPassword.type = "text";

                toggleDetailPasswordButton.textContent =
                    "🙈";

            } else {

                detailPassword.type = "password";

                toggleDetailPasswordButton.textContent =
                    "👁️";
            }
        }
    );


    /* Lock */

    lockButton.addEventListener(
        "click",
        lockVault
    );


    /* Escape */

    document.addEventListener(
        "keydown",
        (event) => {

            if (event.key !== "Escape") {
                return;
            }

            closeAllModals();
        }
    );
}

/* =========================================================
   CLOSE ALL MODALS
========================================================= */

function closeAllModals() {

    createVaultModal.classList.add(
        "hidden"
    );

    settingsModal.classList.add(
        "hidden"
    );

    changeMasterPasswordModal.classList.add(
        "hidden"
    );

    passwordModal.classList.add(
        "hidden"
    );

    detailModal.classList.add(
        "hidden"
    );

    closeRestoreBackupModal(false);

    newMasterPassword.value = "";
    confirmMasterPassword.value = "";
    currentMasterPassword.value = "";
    newMasterPasswordChange.value = "";
    confirmMasterPasswordChange.value = "";
    entryPassword.value = "";
    detailPassword.value = "";

    editingId = null;
    currentDetailId = null;
}

/* =========================================================
   HELPERS
========================================================= */

function showMessage(element, message) {

    if (!element) return;

    element.textContent = message;
}

function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
