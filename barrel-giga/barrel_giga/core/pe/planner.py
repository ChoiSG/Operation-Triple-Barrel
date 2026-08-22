from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

import pefile

from ..artifacts import sha256_bytes
from .ranges import Range, align_up


IMAGE_SCN_MEM_EXECUTE = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]
IMAGE_SCN_MEM_READ = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"]
IMAGE_SCN_MEM_WRITE = pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
PADDING_BYTES = frozenset((0x00, 0x90, 0xCC))
PLACEMENT_ALGORITHM = "pe-wide-split-v2"


@dataclass(frozen=True)
class LayoutSection:
    name: str
    rva: int
    size: int
    raw_offset: int
    characteristics: int
    data: bytes = field(repr=False)

    @property
    def end(self) -> int:
        return self.rva + self.size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_READ)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rva": self.rva,
            "end_rva": self.end,
            "size": self.size,
            "raw_offset": self.raw_offset,
            "characteristics": self.characteristics,
            "executable": self.executable,
            "readable": self.readable,
            "writable": self.writable,
            "sha256": sha256_bytes(self.data),
        }


@dataclass(frozen=True)
class Exclusion:
    start: int
    end: int
    reason: str

    @property
    def range(self) -> Range:
        return Range(self.start, self.end)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_rva": self.start,
            "end_rva": self.end,
            "size": self.end - self.start,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CandidateInterval:
    section: LayoutSection
    start: int
    end: int

    @property
    def range(self) -> Range:
        return Range(self.start, self.end)

    @property
    def size(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict[str, Any]:
        offset = self.start - self.section.rva
        data = self.section.data[offset : offset + self.size]
        padding = sum(value in PADDING_BYTES for value in data)
        return {
            "section": self.section.name,
            "start_rva": self.start,
            "end_rva": self.end,
            "size": self.size,
            "padding_bytes": padding,
            "non_padding_bytes": self.size - padding,
            "sha256": sha256_bytes(data),
        }


@dataclass(frozen=True)
class PlacementRequest:
    name: str
    size: int
    alignment: int
    location: str
    fixed_start: int | None = None
    reserve_size: int | None = None

    @property
    def occupied_size(self) -> int:
        return self.reserve_size if self.reserve_size is not None else self.size


@dataclass(frozen=True)
class PlacementDecision:
    name: str
    section: LayoutSection
    start: int
    end: int
    alignment: int
    location: str
    padding_bytes: int
    non_padding_bytes: int
    score: tuple[int, int, int, int]

    @property
    def range(self) -> Range:
        return Range(self.start, self.end)

    def to_dict(self) -> dict[str, Any]:
        offset = self.start - self.section.rva
        original = self.section.data[offset : offset + (self.end - self.start)]
        return {
            "name": self.name,
            "section": self.section.name,
            "section_characteristics": self.section.characteristics,
            "section_raw_offset": self.section.raw_offset,
            "section_start_rva": self.section.rva,
            "section_end_rva": self.section.end,
            "start_rva": self.start,
            "end_rva": self.end,
            "size": self.end - self.start,
            "alignment": self.alignment,
            "location": self.location,
            "padding_bytes": self.padding_bytes,
            "non_padding_bytes": self.non_padding_bytes,
            "original_sha256": sha256_bytes(original),
            "score": list(self.score),
        }


@dataclass
class PlacementPlan:
    layout: "HostLayout"
    allocations: list[PlacementDecision]
    requests: tuple[PlacementRequest, ...]
    reservations: tuple[dict[str, Any], ...] = ()

    def allocation(self, name: str) -> PlacementDecision:
        matches = [item for item in self.allocations if item.name == name]
        if len(matches) != 1:
            raise ValueError(f"placement plan has {len(matches)} allocations for {name}")
        return matches[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": PLACEMENT_ALGORITHM,
            "layout_digest": self.layout.digest,
            "requests": [
                {
                    "name": item.name,
                    "size": item.size,
                    "alignment": item.alignment,
                    "location": item.location,
                    "fixed_start": item.fixed_start,
                    "reserve_size": item.reserve_size,
                }
                for item in self.requests
            ],
            "allocations": [item.to_dict() for item in self.allocations],
            "reservations": [dict(item) for item in self.reservations],
            "candidate_intervals": [
                item.to_dict() for item in self.layout.intervals
            ],
            "exclusions": [item.to_dict() for item in self.layout.exclusions],
            "sections": [item.to_dict() for item in self.layout.sections],
        }


@dataclass(frozen=True)
class HostLayout:
    sections: tuple[LayoutSection, ...]
    exclusions: tuple[Exclusion, ...]
    intervals: tuple[CandidateInterval, ...]
    digest: str

    def section_for_rva(self, rva: int, size: int = 1) -> LayoutSection | None:
        end = rva + size
        return next(
            (
                section
                for section in self.sections
                if section.rva <= rva and end <= section.end
            ),
            None,
        )

    def to_summary(self) -> dict[str, Any]:
        return {
            "algorithm": PLACEMENT_ALGORITHM,
            "digest": self.digest,
            "sections": [item.to_dict() for item in self.sections],
            "candidate_intervals": [
                item.to_dict() for item in self.intervals
            ],
            "exclusion_count": len(self.exclusions),
            "exclusion_digest": sha256_bytes(
                "\n".join(
                    f"{item.start:x}:{item.end:x}:{item.reason}"
                    for item in self.exclusions
                ).encode("utf-8")
            ),
        }


def conflicting_exclusions(
    layout: HostLayout,
    candidate: Range,
    allowed_reasons: set[str] | None = None,
) -> tuple[Exclusion, ...]:
    allowed = allowed_reasons or set()
    conflicts: list[Exclusion] = []
    for exclusion in layout.exclusions:
        if not candidate.overlaps(exclusion.range):
            continue
        if set(exclusion.reason.split("|")) <= allowed:
            continue
        conflicts.append(exclusion)
    return tuple(conflicts)


def _bounded(start: int, size: int, sections: Iterable[LayoutSection]) -> Range | None:
    if start <= 0 or size <= 0:
        return None
    end = start + size
    for section in sections:
        bounded_start = max(start, section.rva)
        bounded_end = min(end, section.end)
        if bounded_start < bounded_end:
            return Range(bounded_start, bounded_end)
    return None


def _runtime_bounds(image: pefile.PE, rva: int) -> tuple[int, int] | None:
    matches = [
        entry
        for entry in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", [])
        if int(entry.struct.BeginAddress) <= rva < int(entry.struct.EndAddress)
    ]
    if len(matches) != 1:
        return None
    return (
        int(matches[0].struct.BeginAddress),
        int(matches[0].struct.EndAddress),
    )


def _merge_exclusions(values: Iterable[Exclusion]) -> tuple[Exclusion, ...]:
    ordered = sorted(values, key=lambda item: (item.start, item.end, item.reason))
    merged: list[Exclusion] = []
    for value in ordered:
        if value.end <= value.start:
            continue
        if merged and value.start <= merged[-1].end:
            previous = merged[-1]
            reasons = sorted(set(previous.reason.split("|")) | {value.reason})
            merged[-1] = Exclusion(
                previous.start,
                max(previous.end, value.end),
                "|".join(reasons),
            )
        else:
            merged.append(value)
    return tuple(merged)


def _rva_string_size(image: pefile.PE, rva: int, limit: int = 4096) -> int:
    try:
        offset = int(image.get_offset_from_rva(rva))
    except (TypeError, ValueError, pefile.PEFormatError):
        return 0
    data = bytes(image.__data__[offset : offset + limit])
    end = data.find(b"\0")
    return (end + 1) if end >= 0 else 0


def discover_host_layout(image: pefile.PE) -> HostLayout:
    sections: list[LayoutSection] = []
    for section in image.sections:
        size = min(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if size <= 0:
            continue
        raw_offset = int(section.PointerToRawData)
        sections.append(
            LayoutSection(
                name=section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                rva=int(section.VirtualAddress),
                size=size,
                raw_offset=raw_offset,
                characteristics=int(section.Characteristics),
                data=bytes(image.__data__[raw_offset : raw_offset + size]),
            )
        )

    exclusions: list[Exclusion] = []

    def exclude(start: int, size: int, reason: str) -> None:
        remaining_start = start
        remaining_end = start + size
        if start <= 0 or size <= 0:
            return
        for section in sections:
            bounded_start = max(remaining_start, section.rva)
            bounded_end = min(remaining_end, section.end)
            if bounded_start < bounded_end:
                exclusions.append(Exclusion(bounded_start, bounded_end, reason))

    for index, directory in enumerate(image.OPTIONAL_HEADER.DATA_DIRECTORY):
        if index == pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
            continue
        exclude(
            int(directory.VirtualAddress),
            int(directory.Size),
            f"data_directory:{directory.name}",
        )

    image_base = int(image.OPTIONAL_HEADER.ImageBase)
    pointer_size = 8
    for descriptor in getattr(image, "DIRECTORY_ENTRY_IMPORT", []):
        dll_rva = int(descriptor.struct.Name)
        exclude(dll_rva, _rva_string_size(image, dll_rva), "import_dll_name")
        for item in descriptor.imports:
            iat_rva = int(item.address) - image_base
            exclude(iat_rva, pointer_size, "import_iat")
            if item.name:
                try:
                    name_rva = int(image.get_rva_from_offset(int(item.name_offset)))
                except (TypeError, ValueError, pefile.PEFormatError):
                    continue
                exclude(
                    name_rva,
                    2 + len(item.name) + 1,
                    "import_hint_name",
                )

    for descriptor in getattr(image, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
        dll_rva = int(descriptor.struct.szName)
        exclude(
            dll_rva,
            _rva_string_size(image, dll_rva),
            "delay_import_dll_name",
        )
        for item in descriptor.imports:
            address = int(item.address)
            iat_rva = address - image_base if address >= image_base else address
            exclude(iat_rva, pointer_size, "delay_import_iat")
            if item.name:
                name_offset = getattr(item, "name_offset", None)
                if name_offset is None:
                    continue
                try:
                    name_rva = int(
                        image.get_rva_from_offset(int(name_offset))
                    )
                except (TypeError, ValueError, pefile.PEFormatError):
                    continue
                exclude(
                    name_rva,
                    2 + len(item.name) + 1,
                    "delay_import_hint_name",
                )

    for block in getattr(image, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if int(entry.type) == 0:
                continue
            exclude(
                int(entry.rva),
                8 if int(entry.type) == 10 else 4,
                "relocation_target",
            )

    for runtime in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", []):
        exclude(int(runtime.struct.UnwindData), 32, "unwind_info")

    entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry_bounds = _runtime_bounds(image, entrypoint)
    if entry_bounds is not None:
        exclude(
            entry_bounds[0],
            entry_bounds[1] - entry_bounds[0],
            f"entry_function:0x{entrypoint:X}",
        )
    else:
        exclude(entrypoint, 1, f"entry_target:0x{entrypoint:X}")

    export_directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
    if export_directory is not None:
        for symbol in export_directory.symbols:
            target = int(symbol.address)
            directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
            ]
            if int(directory.VirtualAddress) <= target < (
                int(directory.VirtualAddress) + int(directory.Size)
            ):
                continue
            bounds = _runtime_bounds(image, target)
            if bounds is not None:
                exclude(
                    bounds[0],
                    bounds[1] - bounds[0],
                    f"export_function:0x{target:X}",
                )
            else:
                exclude(target, 1, f"export_target:0x{target:X}")

    load_config = getattr(image, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    if load_config is not None:
        table_va = int(
            getattr(load_config.struct, "GuardCFFunctionTable", 0) or 0
        )
        count = int(
            getattr(load_config.struct, "GuardCFFunctionCount", 0) or 0
        )
        guard_flags = int(
            getattr(load_config.struct, "GuardFlags", 0) or 0
        )
        entry_size = 4 + ((guard_flags & 0xF0000000) >> 28)
        if table_va >= image_base and 0 < count <= 10_000_000:
            exclude(
                table_va - image_base,
                count * entry_size,
                "guard_cf_function_table",
            )

    tls = getattr(image, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        callbacks_va = int(
            getattr(tls.struct, "AddressOfCallBacks", 0) or 0
        )
        if callbacks_va >= image_base:
            callbacks_rva = callbacks_va - image_base
            for index in range(1024):
                entry_rva = callbacks_rva + index * pointer_size
                exclude(entry_rva, pointer_size, "tls_callback_array")
                try:
                    entry_offset = int(image.get_offset_from_rva(entry_rva))
                except (TypeError, ValueError, pefile.PEFormatError):
                    break
                raw = bytes(
                    image.__data__[entry_offset : entry_offset + pointer_size]
                )
                if len(raw) != pointer_size:
                    break
                callback_va = int.from_bytes(raw, "little")
                if callback_va == 0:
                    break
                callback_rva = callback_va - image_base
                bounds = _runtime_bounds(image, callback_rva)
                if bounds is not None:
                    exclude(
                        bounds[0],
                        bounds[1] - bounds[0],
                        f"tls_callback_function:0x{callback_rva:X}",
                    )
                else:
                    exclude(
                        callback_rva,
                        1,
                        f"tls_callback_target:0x{callback_rva:X}",
                    )

    merged = _merge_exclusions(exclusions)
    intervals: list[CandidateInterval] = []
    for section in sections:
        cursor = section.rva
        for exclusion in merged:
            if exclusion.end <= section.rva:
                continue
            if exclusion.start >= section.end:
                break
            if cursor < exclusion.start:
                intervals.append(
                    CandidateInterval(section, cursor, exclusion.start)
                )
            cursor = max(cursor, exclusion.end)
        if cursor < section.end:
            intervals.append(CandidateInterval(section, cursor, section.end))

    digest = hashlib.sha256()
    digest.update(PLACEMENT_ALGORITHM.encode("ascii"))
    for section in sections:
        digest.update(
            f"{section.name}:{section.rva:x}:{section.size:x}:"
            f"{section.characteristics:x}:".encode("utf-8")
        )
        digest.update(hashlib.sha256(section.data).digest())
    for exclusion in merged:
        digest.update(
            f"{exclusion.start:x}:{exclusion.end:x}:{exclusion.reason}\n".encode(
                "utf-8"
            )
        )
    return HostLayout(
        sections=tuple(sections),
        exclusions=merged,
        intervals=tuple(intervals),
        digest=digest.hexdigest().upper(),
    )


def _section_rank(section: LayoutSection, location: str) -> int | None:
    lowered = section.name.casefold()
    if location == "code":
        if not section.executable:
            return None
        return 0 if lowered == ".text" else 10
    if location in {"rdata", "data"}:
        if not section.readable or section.writable or section.executable:
            return None
        if lowered == ".rdata":
            return 0
        if lowered in {".pdata", ".reloc", ".rsrc"}:
            return 20
        return 10
    raise ValueError(f"unsupported placement location {location!r}")


class PlacementPlanner:
    def __init__(self, layout: HostLayout):
        self.layout = layout
        self.used: list[Range] = []
        self._non_padding_prefix: dict[int, list[int]] = {}
        for section in layout.sections:
            prefix = [0]
            count = 0
            for value in section.data:
                if value not in PADDING_BYTES:
                    count += 1
                prefix.append(count)
            self._non_padding_prefix[section.rva] = prefix

    def _free_intervals(self, interval: CandidateInterval) -> list[Range]:
        cursor = interval.start
        result: list[Range] = []
        for used in sorted(self.used, key=lambda item: item.start):
            if used.end <= interval.start:
                continue
            if used.start >= interval.end:
                break
            if cursor < used.start:
                result.append(Range(cursor, min(used.start, interval.end)))
            cursor = max(cursor, used.end)
        if cursor < interval.end:
            result.append(Range(cursor, interval.end))
        return result

    def _decision(
        self,
        request: PlacementRequest,
        section: LayoutSection,
        start: int,
        section_rank: int,
        alignment_waste: int,
    ) -> PlacementDecision:
        end = start + request.size
        offset = start - section.rva
        prefix = self._non_padding_prefix[section.rva]
        non_padding = prefix[offset + request.size] - prefix[offset]
        padding = request.size - non_padding
        score = (section_rank, non_padding, alignment_waste, start)
        return PlacementDecision(
            name=request.name,
            section=section,
            start=start,
            end=end,
            alignment=request.alignment,
            location=request.location,
            padding_bytes=padding,
            non_padding_bytes=non_padding,
            score=score,
        )

    def allocate(self, request: PlacementRequest) -> PlacementDecision:
        if request.size <= 0:
            raise ValueError(f"{request.name} placement size must be positive")
        if request.occupied_size < request.size:
            raise ValueError(
                f"{request.name} reserve_size cannot be smaller than size"
            )
        if (
            request.alignment <= 0
            or request.alignment & (request.alignment - 1)
        ):
            raise ValueError(
                f"{request.name} alignment must be a positive power of two"
            )

        candidates: list[PlacementDecision] = []
        for interval in self.layout.intervals:
            rank = _section_rank(interval.section, request.location)
            if rank is None:
                continue
            for free in self._free_intervals(interval):
                if request.fixed_start is not None:
                    starts = (
                        [request.fixed_start]
                        if free.start <= request.fixed_start
                        and request.fixed_start + request.occupied_size <= free.end
                        and request.fixed_start % request.alignment == 0
                        else []
                    )
                else:
                    first = align_up(free.start, request.alignment)
                    last = free.end - request.occupied_size
                    starts = (
                        range(first, last + 1, request.alignment)
                        if first <= last
                        else ()
                    )
                for start in starts:
                    candidates.append(
                        self._decision(
                            request,
                            interval.section,
                            start,
                            rank,
                            start - free.start,
                        )
                    )
        if not candidates:
            fixed = (
                f" at RVA 0x{request.fixed_start:X}"
                if request.fixed_start is not None
                else ""
            )
            raise ValueError(
                f"no {request.location} range of {request.size} bytes is "
                f"available for {request.name}{fixed}"
            )
        selected = min(candidates, key=lambda item: item.score)
        self.used.append(
            Range(selected.start, selected.start + request.occupied_size)
        )
        self.used.sort(key=lambda item: item.start)
        return selected

    def allocate_override(
        self,
        request: PlacementRequest,
        allowed_exclusion_reasons: set[str],
    ) -> PlacementDecision:
        if request.fixed_start is None:
            raise ValueError("override placement requires fixed_start")
        if request.size <= 0:
            raise ValueError(f"{request.name} placement size must be positive")
        if request.occupied_size < request.size:
            raise ValueError(
                f"{request.name} reserve_size cannot be smaller than size"
            )
        if request.fixed_start % request.alignment:
            raise ValueError(
                f"{request.name} fixed placement is not {request.alignment}-byte aligned"
            )
        section = self.layout.section_for_rva(
            request.fixed_start, request.occupied_size
        )
        if section is None:
            raise ValueError(
                f"{request.name} fixed placement is outside mapped file-backed sections"
            )
        rank = _section_rank(section, request.location)
        if rank is None:
            raise ValueError(
                f"{request.name} fixed placement is not compatible with "
                f"{request.location}"
            )
        requested = Range(
            request.fixed_start,
            request.fixed_start + request.occupied_size,
        )
        if any(requested.overlaps(item) for item in self.used):
            raise ValueError(
                f"{request.name} fixed placement overlaps another allocation"
            )
        conflicts = conflicting_exclusions(
            self.layout, requested, allowed_exclusion_reasons
        )
        if conflicts:
            raise ValueError(
                f"{request.name} fixed placement overlaps protected "
                f"{conflicts[0].reason} metadata"
            )
        selected = self._decision(request, section, request.fixed_start, rank, 0)
        self.used.append(requested)
        self.used.sort(key=lambda item: item.start)
        return selected

    def plan(self, requests: Iterable[PlacementRequest]) -> PlacementPlan:
        values = tuple(requests)
        allocations = [self.allocate(item) for item in values]
        return PlacementPlan(self.layout, allocations, values)

