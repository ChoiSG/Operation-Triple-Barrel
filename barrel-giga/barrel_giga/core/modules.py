from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import StrictUndefined, Template

from .config import REQUIRED_SLOTS, Recipe


class ModuleError(ValueError):
    pass


@dataclass(frozen=True)
class ModuleManifest:
    name: str
    slot: str
    directory: Path
    fragment: Path
    fixture_only: bool
    host_behavior: str | None
    required_imports: tuple[str, ...]
    requires: tuple[str, ...]
    conflicts: tuple[str, ...]
    exports: tuple[str, ...]
    config: dict[str, Any]
    digest: str

    @property
    def qualified_name(self) -> str:
        return f"{self.slot}/{self.name}"

    def render(self, context: dict[str, Any]) -> str:
        values = dict(self.config)
        values.update(context)
        return Template(
            self.fragment.read_text(encoding="utf-8"),
            undefined=StrictUndefined,
            keep_trailing_newline=True,
        ).render(**values)


class ModuleRegistry:
    def __init__(self, root: Path):
        self.root = root
        self.modules: dict[str, dict[str, ModuleManifest]] = {
            slot: {} for slot in REQUIRED_SLOTS
        }

    def discover(self) -> "ModuleRegistry":
        for manifest_path in sorted(self.root.glob("*/*/module.toml")):
            raw_bytes = manifest_path.read_bytes()
            raw = tomllib.loads(raw_bytes.decode("utf-8"))
            directory = manifest_path.parent
            name = raw.get("name")
            slot = raw.get("slot")
            if not isinstance(name, str) or not name:
                raise ModuleError(f"{manifest_path}: missing module name")
            if slot not in REQUIRED_SLOTS:
                raise ModuleError(f"{manifest_path}: invalid slot {slot!r}")
            if directory.parent.name != slot or directory.name != name:
                raise ModuleError(
                    f"{manifest_path}: filesystem path must be modules/{slot}/{name}"
                )
            fragment = directory / raw.get("fragment", "fragment.c.j2")
            if not fragment.is_file():
                raise ModuleError(f"{manifest_path}: missing fragment {fragment.name}")
            if name in self.modules[slot]:
                raise ModuleError(f"duplicate module {slot}/{name}")
            fixture_only = raw.get("fixture_only", False)
            if not isinstance(fixture_only, bool):
                raise ModuleError(
                    f"{manifest_path}: fixture_only must be true or false"
                )
            if slot == "execute" and "fixture_only" not in raw:
                raise ModuleError(
                    f"{manifest_path}: execute modules must declare fixture_only"
                )
            host_behavior = raw.get("host_behavior")
            if host_behavior is not None and (
                not isinstance(host_behavior, str) or not host_behavior
            ):
                raise ModuleError(
                    f"{manifest_path}: host_behavior must be a non-empty string"
                )
            digest = hashlib.sha256(raw_bytes + fragment.read_bytes()).hexdigest().upper()
            self.modules[slot][name] = ModuleManifest(
                name=name,
                slot=slot,
                directory=directory,
                fragment=fragment,
                fixture_only=fixture_only,
                host_behavior=host_behavior,
                required_imports=tuple(raw.get("required_imports", [])),
                requires=tuple(raw.get("requires", [])),
                conflicts=tuple(raw.get("conflicts", [])),
                exports=tuple(raw.get("exports", [])),
                config=dict(raw.get("config", {})),
                digest=digest,
            )
        return self

    def select(self, recipe: Recipe) -> list[ModuleManifest]:
        selected: list[ModuleManifest] = []
        for slot, name in recipe.as_dict().items():
            try:
                selected.append(self.modules[slot][name])
            except KeyError as exc:
                raise ModuleError(f"unknown module {slot}/{name}") from exc
        selected_names = {module.qualified_name for module in selected}
        for module in selected:
            missing = set(module.requires) - selected_names
            conflicts = set(module.conflicts) & selected_names
            if missing:
                raise ModuleError(
                    f"{module.qualified_name} requires {', '.join(sorted(missing))}"
                )
            if conflicts:
                raise ModuleError(
                    f"{module.qualified_name} conflicts with {', '.join(sorted(conflicts))}"
                )
        return selected

    def validate_all(self) -> None:
        missing = [slot for slot in REQUIRED_SLOTS if not self.modules[slot]]
        if missing:
            raise ModuleError(f"no implementations for slots: {', '.join(missing)}")
        for slot_modules in self.modules.values():
            for module in slot_modules.values():
                if module.slot == "execute" and not isinstance(
                    module.fixture_only, bool
                ):
                    raise ModuleError(
                        f"{module.qualified_name}: fixture_only must be explicit"
                    )
                if module.slot == "pe_invoke" and module.host_behavior not in {
                    "entrypoint_replaced",
                    "entry_function_backdoored",
                    "worker",
                    "dllmain_replaced_worker",
                    "dllmain_backdoored_worker",
                    "named_export_replaced",
                    "named_export_backdoored",
                    "callback_only_destructive",
                }:
                    raise ModuleError(
                        f"{module.qualified_name}: invalid or missing host_behavior"
                    )
                for item in (*module.requires, *module.conflicts):
                    if "/" not in item:
                        raise ModuleError(
                            f"{module.qualified_name}: dependency must be slot/name: {item}"
                        )
                    slot, name = item.split("/", 1)
                    if slot not in self.modules or name not in self.modules[slot]:
                        raise ModuleError(
                            f"{module.qualified_name}: unknown dependency {item}"
                        )

    def rows(self) -> list[tuple[str, str, str]]:
        result: list[tuple[str, str, str]] = []
        for slot in REQUIRED_SLOTS:
            for name, module in sorted(self.modules[slot].items()):
                result.append((slot, name, ", ".join(module.required_imports) or "-"))
        return result

