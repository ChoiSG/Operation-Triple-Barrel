from __future__ import annotations

from dataclasses import dataclass


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass(frozen=True)
class Range:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("invalid half-open range")

    @property
    def size(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Range") -> bool:
        return self.start < other.end and other.start < self.end


class RangeAllocator:
    def __init__(self, start: int, end: int):
        if end < start:
            raise ValueError("allocator end precedes start")
        self.bounds = Range(start, end)
        self.used: list[Range] = []

    def reserve(self, start: int, size: int) -> Range:
        candidate = Range(start, start + size)
        if candidate.start < self.bounds.start or candidate.end > self.bounds.end:
            raise ValueError("range is outside allocator bounds")
        if any(candidate.overlaps(existing) for existing in self.used):
            raise ValueError("range overlaps an existing reservation")
        self.used.append(candidate)
        self.used.sort(key=lambda item: item.start)
        return candidate

    def allocate(self, size: int, alignment: int = 1) -> Range:
        if size < 0:
            raise ValueError("size cannot be negative")
        cursor = align_up(self.bounds.start, alignment)
        for existing in self.used:
            if cursor + size <= existing.start:
                return self.reserve(cursor, size)
            cursor = align_up(max(cursor, existing.end), alignment)
        if cursor + size <= self.bounds.end:
            return self.reserve(cursor, size)
        raise ValueError(f"no range of {size} bytes is available")


