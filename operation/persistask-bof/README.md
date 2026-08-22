# persistask

Cobalt Strike BOF for scheduled task management via COM (`ITaskService`). 

## Build

Install the MinGW cross-compilers
```
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
```

Compile
```
make          # produces persistask.x64.o / persistask.x86.o
make test     # standalone .exe for local testing
make check    # cppcheck static analysis
```

## Setup

Load `persistask.cna` in the Script Manager.

## Usage

### Add a persistent task

```
persistask add <name> <command> [args] [working_dir] [trigger] [--no-elevate]
```

- **trigger**: `logon` (default), `boot`, or `unlock`
- Tasks register at `RunLevel=Highest` (unfiltered token / UAC bypass) unless `--no-elevate` is passed.

### Execute via one-shot task

```
persistask exec <name> <command> [args] [working_dir] [--no-elevate]
```

Registers an on-demand task, runs it immediately, then deletes it. Execution is detached from the current beacon session.

### List tasks

```
persistask list [filter]
```

Enumerates all scheduled tasks (recursive). Optional case-insensitive filter on task name/path.

### Remove a task

```
persistask remove <name>
```

## Notes

- `--no-elevate` can appear anywhere after the required args; positional order of optional args is preserved.
- `exec` is useful for running payloads outside the beacon process tree.

## Credits & Original Project 

- https://github.com/nickzer0/PersisTask-BOF, [@nickzer0](https://github.com/nickzer0)