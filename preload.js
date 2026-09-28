"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("lockboxClipboard", {
    copy: (text) => {
        if (typeof text !== "string") {
            return Promise.reject(
                new TypeError("Clipboard text must be a string.")
            );
        }

        return ipcRenderer.invoke("lockbox:copy-to-clipboard", text);
    }
});
