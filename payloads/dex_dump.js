/**
 * JiaguSentinel Pro v2.0 — Enhanced DEX Memory Dumper
 * =====================================================
 * Advanced Frida payload for runtime DEX extraction from
 * 360 Jiagu-protected applications.
 *
 * Features:
 * - Multi-version DEX magic byte scanning (v035–v041)
 * - DexFile constructor interception
 * - ART InMemoryDexClassLoader hook
 * - File size validation from DEX headers
 * - Anti-detection: patches ro.debuggable reads
 * - Dumps all classes.dex segments simultaneously
 *
 * Usage: Loaded by DynamicEngine or manually via frida -l dex_dump.js
 */

'use strict';

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════

const CONFIG = {
    DUMP_DIR: "/data/local/tmp/sentinel_dumps/",
    MIN_DEX_SIZE: 112,          // Minimum valid DEX header
    MAX_DEX_SIZE: 100 * 1024 * 1024,  // 100 MB sanity limit
    SCAN_DELAY_MS: 3000,        // Wait for unpacker to decrypt
    RESCAN_INTERVAL_MS: 5000,   // Periodic rescan interval
    MAX_RESCANS: 6,             // Total rescans before giving up
    VERBOSE: true,
};

// DEX magic pattern: "dex\n0XX\0" where XX is 35-41
const DEX_SCAN_PATTERN = "64 65 78 0A 30 3? ?? 00";

let dexCounter = 0;
const dumpedAddresses = new Set();

// ═══════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════

function log(msg) {
    if (CONFIG.VERBOSE) {
        send({ type: "log", message: "[DexDump] " + msg });
    }
}

function ensureDumpDir() {
    try {
        const mkdirPtr = Module.findExportByName("libc.so", "mkdir");
        if (mkdirPtr) {
            const mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
            mkdir(Memory.allocUtf8String(CONFIG.DUMP_DIR), 0o755);
        }
    } catch (e) {
        log("mkdir failed: " + e);
    }
}

function validateDexHeader(ptr) {
    try {
        // Check magic bytes
        const magic = ptr.readByteArray(4);
        const magicStr = Array.from(new Uint8Array(magic))
            .map(b => String.fromCharCode(b))
            .join('');
        if (magicStr !== "dex\n") return null;

        // Read version
        const version = ptr.add(4).readCString(3);

        // Read file_size (offset 32, uint32 LE)
        const fileSize = ptr.add(32).readU32();
        if (fileSize < CONFIG.MIN_DEX_SIZE || fileSize > CONFIG.MAX_DEX_SIZE) {
            return null;
        }

        // Read header_size (offset 36, should be 0x70 = 112)
        const headerSize = ptr.add(36).readU32();
        if (headerSize !== 0x70) return null;

        // Read checksum (offset 8, should be non-zero)
        const checksum = ptr.add(8).readU32();
        if (checksum === 0) return null;

        // Read string_ids_size (offset 56) — sanity check
        const stringIdsSize = ptr.add(56).readU32();
        if (stringIdsSize === 0 || stringIdsSize > 0xFFFFFF) return null;

        return {
            version: version,
            fileSize: fileSize,
            checksum: checksum,
            headerSize: headerSize,
            stringIdsSize: stringIdsSize,
        };
    } catch (e) {
        return null;
    }
}

function dumpDex(baseAddr, size, tag) {
    const addrKey = baseAddr.toString();
    if (dumpedAddresses.has(addrKey)) return null;
    dumpedAddresses.add(addrKey);

    try {
        const filename = CONFIG.DUMP_DIR + "sentinel_" + tag + "_" + dexCounter + ".dex";
        const fd = new File(filename, "wb");
        fd.write(baseAddr.readByteArray(size));
        fd.flush();
        fd.close();

        dexCounter++;
        log("Dumped: " + filename + " (" + size + " bytes)");
        return {
            address: addrKey,
            size: size,
            path: filename,
            tag: tag,
        };
    } catch (e) {
        log("Dump failed at " + addrKey + ": " + e);
        return null;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Memory Scanner — Brute-force scan for DEX in all readable regions
// ═══════════════════════════════════════════════════════════════════

function scanMemoryForDex() {
    log("Starting memory scan for DEX files...");
    const results = [];

    Process.enumerateRanges('r--').forEach(function (range) {
        if (range.size < CONFIG.MIN_DEX_SIZE) return;

        try {
            const scanResults = Memory.scanSync(
                range.base, range.size, DEX_SCAN_PATTERN
            );

            scanResults.forEach(function (match) {
                const header = validateDexHeader(match.address);
                if (header) {
                    // Verify the entire DEX is within the memory range
                    const endAddr = match.address.add(header.fileSize);
                    const rangeEnd = range.base.add(range.size);

                    if (endAddr.compare(rangeEnd) <= 0) {
                        const result = dumpDex(
                            match.address,
                            header.fileSize,
                            "mem_v" + header.version
                        );
                        if (result) {
                            result.version = header.version;
                            results.push(result);
                        }
                    }
                }
            });
        } catch (e) {
            // Skip unreadable ranges
        }
    });

    log("Memory scan complete: " + results.length + " DEX found");
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// ART Hooks — Intercept DEX loading at the framework level
// ═══════════════════════════════════════════════════════════════════

function hookDexFileConstructor() {
    try {
        // Hook art::DexFile::DexFile constructor
        const symbols = Module.enumerateSymbolsSync("libart.so");
        const dexFileSymbols = symbols.filter(function (sym) {
            return sym.name.indexOf("DexFile") !== -1 &&
                sym.name.indexOf("OpenMemory") !== -1;
        });

        dexFileSymbols.forEach(function (sym) {
            try {
                Interceptor.attach(sym.address, {
                    onEnter: function (args) {
                        // args[0] = this, args[1] = base, args[2] = size
                        try {
                            const base = args[1];
                            const header = validateDexHeader(base);
                            if (header) {
                                log("DexFile::OpenMemory intercepted: " +
                                    header.fileSize + " bytes, v" + header.version);
                                const result = dumpDex(
                                    base, header.fileSize,
                                    "hook_v" + header.version
                                );
                                if (result) {
                                    send({
                                        type: "dex_hook",
                                        result: result,
                                    });
                                }
                            }
                        } catch (e) { }
                    }
                });
                log("Hooked: " + sym.name);
            } catch (e) { }
        });
    } catch (e) {
        log("DexFile hook failed: " + e);
    }
}

function hookInMemoryDexClassLoader() {
    try {
        // Java-level hook for InMemoryDexClassLoader
        Java.perform(function () {
            try {
                const InMemoryDexClassLoader = Java.use(
                    "dalvik.system.InMemoryDexClassLoader"
                );
                InMemoryDexClassLoader.$init.overload(
                    "java.nio.ByteBuffer", "java.lang.ClassLoader"
                ).implementation = function (buffer, parent) {
                    log("InMemoryDexClassLoader intercepted!");
                    try {
                        const size = buffer.remaining();
                        const bytes = new Uint8Array(size);
                        const pos = buffer.position();
                        for (let i = 0; i < size; i++) {
                            bytes[i] = buffer.get(pos + i) & 0xFF;
                        }
                        const tmpFile = CONFIG.DUMP_DIR + "sentinel_inmem_" +
                            dexCounter + ".dex";
                        const fd = new File(tmpFile, "wb");
                        fd.write(bytes.buffer);
                        fd.flush();
                        fd.close();
                        dexCounter++;
                        send({
                            type: "dex_hook",
                            result: {
                                address: "InMemoryDexClassLoader",
                                size: size,
                                path: tmpFile,
                                tag: "inmem",
                            },
                        });
                    } catch (e) {
                        log("InMem dump error: " + e);
                    }
                    return this.$init(buffer, parent);
                };
                log("Hooked InMemoryDexClassLoader");
            } catch (e) {
                log("InMemoryDexClassLoader not available: " + e);
            }
        });
    } catch (e) {
        log("Java hook failed: " + e);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Anti-Detection: Patch ro.debuggable checks
// ═══════════════════════════════════════════════════════════════════

function patchDebuggableCheck() {
    try {
        const propGet = Module.findExportByName(
            "libc.so", "__system_property_get"
        );
        if (propGet) {
            Interceptor.attach(propGet, {
                onEnter: function (args) {
                    const name = args[0].readCString();
                    if (name === "ro.debuggable") {
                        this._patchDebug = true;
                        this._valuePtr = args[1];
                    }
                },
                onLeave: function (retval) {
                    if (this._patchDebug && this._valuePtr) {
                        this._valuePtr.writeUtf8String("0");
                    }
                }
            });
            log("Patched ro.debuggable check");
        }
    } catch (e) {
        log("Debuggable patch failed: " + e);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main Execution — Orchestrate all hooks and scans
// ═══════════════════════════════════════════════════════════════════

(function main() {
    send({ type: "payload_init", name: "dex_dump.js", version: "2.0" });

    ensureDumpDir();
    patchDebuggableCheck();
    hookDexFileConstructor();
    hookInMemoryDexClassLoader();

    // Initial delayed scan — wait for unpacker to finish
    setTimeout(function () {
        const initialResults = scanMemoryForDex();
        send({
            type: "dex_scan",
            results: initialResults,
            total: initialResults.length,
            phase: "initial",
        });

        // Periodic rescans to catch late-decrypted DEX
        let rescans = 0;
        const rescanTimer = setInterval(function () {
            rescans++;
            if (rescans >= CONFIG.MAX_RESCANS) {
                clearInterval(rescanTimer);
                log("Rescan limit reached. Scan complete.");
                send({ type: "scan_complete", total_dumped: dexCounter });
                return;
            }
            log("Rescan #" + rescans + "...");
            const newResults = scanMemoryForDex();
            if (newResults.length > 0) {
                send({
                    type: "dex_scan",
                    results: newResults,
                    total: newResults.length,
                    phase: "rescan_" + rescans,
                });
            }
        }, CONFIG.RESCAN_INTERVAL_MS);

    }, CONFIG.SCAN_DELAY_MS);
})();
