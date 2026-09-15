"""Bounded local draft parsing and exact original-byte references for repair.

No authority, signature, resource or custody is accepted here. A DraftJson is
only parsed data; new repair consumers must use parse_new_wire and then their
own closed schema and complete authority verifier. Historical originals use the
byte resolver, never the new JSON parser or a canonical reserialization.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, fields as dataclass_fields
import hashlib
import hmac
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Iterable


U53_MAX = 9007199254740991
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_HEX = frozenset("0123456789abcdefABCDEF")


class RepairWireError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str):
    raise RepairWireError(code)


def _immutable(*args, **kwargs):
    raise TypeError("repair_draft_immutable")


class _DraftDict(dict):
    """Read-only JSON data; only the internal parser uses base-class writes."""

    def __init__(self):
        pass

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _immutable
    __ior__ = _immutable


class _DraftList(list):
    def __init__(self):
        pass

    __setitem__ = __delitem__ = append = clear = extend = insert = pop = _immutable
    remove = reverse = sort = __iadd__ = __imul__ = _immutable


def u53(value: Any, minimum: int = 0) -> int:
    if (type(minimum) is not int or not 0 <= minimum <= U53_MAX
            or type(value) is not int or not minimum <= value <= U53_MAX):
        _fail("repair_invalid_integer")
    return value


def object_fields(value: Any, expected: Iterable[str]) -> dict:
    """A schema helper, not a generic JSON object's authority validator."""
    expected = frozenset(expected)
    if (type(value) not in (dict, _DraftDict) or any(type(key) is not str for key in value)
            or value.keys() != expected):
        _fail("repair_unknown_fields")
    return value


@dataclass(frozen=True, slots=True)
class RepairPolicy:
    """Caller-chosen finite local limits; none are a deployed protocol policy."""

    max_document_bytes: int
    max_total_bytes: int
    max_nodes: int
    max_depth: int
    max_string_bytes: int
    max_hash_bytes: int
    max_hashes: int
    max_entries: int
    max_retained_bytes: int

    def __post_init__(self):
        for field in dataclass_fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or not 1 <= value <= U53_MAX:
                _fail("repair_invalid_policy")


class RepairBudget:
    """One cumulative meter. Failed work is not refunded or silently reset.

    input_bytes counts buffers admitted for inspection; output_bytes counts
    actual canonical/pack output and output copies. nodes/string_bytes include
    the second canonical traversal; nodes also counts decoded pack headers.
    retained_bytes/entries describe resolver and pack/index holdings, not all
    interpreter heap allocations. No signature verifier is called.
    One private reentrant lock serializes whole public operations sharing this
    budget, including resolver holdings. This is not a database writer lock.
    """

    __slots__ = ("__policy", "__lock", "__usage")

    def __init__(self, policy: RepairPolicy):
        if type(policy) is not RepairPolicy or hasattr(self, "_RepairBudget__usage"):
            _fail("repair_invalid_policy")
        object.__setattr__(self, "_RepairBudget__policy", policy)
        object.__setattr__(self, "_RepairBudget__lock", RLock())
        object.__setattr__(self, "_RepairBudget__usage", dict(
            input_bytes=0, output_bytes=0, nodes=0, string_bytes=0, max_depth=0,
            hash_bytes=0, hashes=0, entries=0, retained_bytes=0, signature_checks=0))

    def __setattr__(self, name, value):
        raise AttributeError("repair_budget_immutable")

    def __delattr__(self, name):
        raise AttributeError("repair_budget_immutable")

    @property
    def _lock(self):
        return self.__lock

    @property
    def _usage(self):
        # Module readers may inspect the ledger; retained charges go through
        # _retain. Ordinary instance writes cannot reset this live dictionary.
        return MappingProxyType(self.__usage)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return self.__usage.copy()

    @property
    def policy(self) -> RepairPolicy:
        return self.__policy

    def _fits(self, field: str, amount: int, limit: int):
        if amount > limit - self.__usage[field]:
            _fail("repair_over_budget")

    def _bytes(self, field: str, amount: int):
        total = self.__usage["input_bytes"] + self.__usage["output_bytes"]
        if amount > self.policy.max_total_bytes - total:
            _fail("repair_over_budget")
        self.__usage[field] += amount

    def _node(self, depth: int):
        if depth > self.policy.max_depth:
            _fail("repair_over_budget")
        self._fits("nodes", 1, self.policy.max_nodes)
        self.__usage["nodes"] += 1
        self.__usage["max_depth"] = max(self.__usage["max_depth"], depth)

    def _string(self, size: int):
        if size > self.policy.max_string_bytes:
            _fail("repair_over_budget")
        if size > U53_MAX - self.__usage["string_bytes"]:
            _fail("repair_over_budget")
        self.__usage["string_bytes"] += size

    def _hash(self, raw: bytes) -> str:
        self._fits("hashes", 1, self.policy.max_hashes)
        self._fits("hash_bytes", len(raw), self.policy.max_hash_bytes)
        result = hashlib.sha256(raw).hexdigest()
        self.__usage["hashes"] += 1
        self.__usage["hash_bytes"] += len(raw)
        return result

    def _retain(self, size: int, count: int = 1):
        u53(size)
        u53(count, 1)
        self._fits("entries", count, self.policy.max_entries)
        self._fits("retained_bytes", size, self.policy.max_retained_bytes)
        self.__usage["entries"] += count
        self.__usage["retained_bytes"] += size


def _context(policy: RepairPolicy, budget: RepairBudget):
    if type(policy) is not RepairPolicy or type(budget) is not RepairBudget:
        _fail("repair_invalid_policy")
    try:
        if budget.policy != policy:
            _fail("repair_invalid_policy")
    except AttributeError:  # A matching type made without its constructor.
        _fail("repair_invalid_policy")


def _raw_size(raw: Any, policy: RepairPolicy) -> int:
    if type(raw) not in (bytes, bytearray, memoryview):
        _fail("repair_invalid_bytes")
    try:
        size = raw.nbytes if type(raw) is memoryview else len(raw)
    except ValueError:
        _fail("repair_invalid_bytes")
    if size > policy.max_document_bytes:
        _fail("repair_over_budget")
    return size


def _snapshot(raw: Any, policy: RepairPolicy, budget: RepairBudget) -> bytes:
    size = _raw_size(raw, policy)
    if type(raw) is bytes:
        budget._bytes("input_bytes", size)
        return raw  # Immutable input needs no physical copy.
    try:
        # Hold a buffer export so bytearray cannot resize between cap and copy.
        with memoryview(raw) as view:
            size = _raw_size(view, policy)
            budget._bytes("input_bytes", size)  # Before copying or decoding.
            return view.tobytes()
    except (ValueError, BufferError):
        _fail("repair_invalid_bytes")


def _utf8_size(char: str) -> int:
    cp = ord(char)
    return 1 if cp < 0x80 else 2 if cp < 0x800 else 3 if cp < 0x10000 else 4


@dataclass(frozen=True)
class DraftJson:
    """Fixed raw and read-only parsed data, with no schema or authority verdict."""

    raw: bytes
    value: Any


class _Parser:
    """Iterative containers: configured depth does not depend on Python recursion."""

    def __init__(self, text: str, budget: RepairBudget):
        self.text, self.pos, self.budget = text, 0, budget

    def _space(self):
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self.pos += 1

    def _take(self, expected: str):
        if self.pos >= len(self.text) or self.text[self.pos] != expected:
            _fail("repair_invalid_json")
        self.pos += 1

    def _hex4(self) -> int:
        digits = self.text[self.pos:self.pos + 4]
        if len(digits) != 4 or any(c not in _HEX for c in digits):
            _fail("repair_invalid_json")
        self.pos += 4
        return int(digits, 16)

    def _string(self) -> str:
        self._take('"')
        pieces, size = [], 0
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return "".join(pieces)
            if char == "\\":
                if self.pos >= len(self.text):
                    _fail("repair_invalid_json")
                escaped = self.text[self.pos]
                self.pos += 1
                if escaped == "u":
                    cp = self._hex4()
                    if 0xD800 <= cp <= 0xDBFF:
                        if self.text[self.pos:self.pos + 2] != "\\u":
                            _fail("repair_invalid_unicode")
                        self.pos += 2
                        low = self._hex4()
                        if not 0xDC00 <= low <= 0xDFFF:
                            _fail("repair_invalid_unicode")
                        cp = 0x10000 + ((cp - 0xD800) << 10) + low - 0xDC00
                    elif 0xDC00 <= cp <= 0xDFFF:
                        _fail("repair_invalid_unicode")
                    char = chr(cp)
                else:
                    escapes = {'"': '"', "\\": "\\", "/": "/", "b": "\b",
                               "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                    if escaped not in escapes:
                        _fail("repair_invalid_json")
                    char = escapes[escaped]
            elif ord(char) < 0x20:
                _fail("repair_invalid_json")
            piece_size = _utf8_size(char)
            size += piece_size
            if size > self.budget.policy.max_string_bytes:
                _fail("repair_over_budget")
            self.budget._string(piece_size)
            pieces.append(char)
        _fail("repair_invalid_json")

    def _value(self, depth: int):
        self._space()
        if self.pos == len(self.text):
            _fail("repair_invalid_json")
        self.budget._node(depth)
        char = self.text[self.pos]
        if char in "{[":
            self.pos += 1
            value = _DraftDict() if char == "{" else _DraftList()
            return value, [value, depth, "first"]
        if char == '"':
            return self._string(), None
        for literal, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(literal, self.pos):
                self.pos += len(literal)
                return value, None
        start = self.pos
        while (self.pos < len(self.text)
               and self.text[self.pos] not in " \t\r\n,]}"):
            self.pos += 1
        token = self.text[start:self.pos]
        if _INTEGER.fullmatch(token) is None:
            _fail("repair_invalid_json")
        if len(token) > 16:
            _fail("repair_invalid_integer")
        return u53(int(token)), None

    def parse(self):
        value, first = self._value(1)
        stack = [] if first is None else [first]
        while stack:
            frame = stack[-1]
            container, depth, state = frame
            self._space()
            end = "}" if type(container) is _DraftDict else "]"
            if state == "after":
                if self.pos < len(self.text) and self.text[self.pos] == end:
                    self.pos += 1
                    stack.pop()
                    continue
                self._take(",")
                frame[2] = "next"
                self._space()
            elif state == "first" and self.pos < len(self.text) and self.text[self.pos] == end:
                self.pos += 1
                stack.pop()
                continue
            if type(container) is _DraftDict:
                self.budget._node(depth + 1)
                key = self._string()
                if key in container:
                    _fail("repair_invalid_json")
                self._space()
                self._take(":")
                child, child_frame = self._value(depth + 1)
                dict.__setitem__(container, key, child)
            else:
                child, child_frame = self._value(depth + 1)
                list.append(container, child)
            frame[2] = "after"
            if child_frame is not None:
                stack.append(child_frame)
        self._space()
        if self.pos != len(self.text):
            _fail("repair_invalid_json")
        return value


def parse_new_json(raw: bytes, policy: RepairPolicy, budget: RepairBudget) -> DraftJson:
    """Strict JSON draft, including bool/null; numbers have U53 integer lexemes.

    This diagnostic parser preserves noncanonical whitespace/escapes. It is not
    the new repair wire acceptance entry: use parse_new_wire for that check.
    """
    _context(policy, budget)
    with budget._lock:
        original = _snapshot(raw, policy, budget)
        try:
            text = original.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _fail("repair_invalid_utf8")
        return DraftJson(original, _Parser(text, budget).parse())


def _canonical(value: Any, budget: RepairBudget) -> bytes:
    output = bytearray()

    def emit(raw: bytes):
        if len(raw) > budget.policy.max_document_bytes - len(output):
            _fail("repair_over_budget")
        budget._bytes("output_bytes", len(raw))
        output.extend(raw)

    def string(value: str):
        budget._string(sum(_utf8_size(char) for char in value))
        emit(b'"')
        escapes = {'"': b'\\"', "\\": b"\\\\", "\b": b"\\b", "\f": b"\\f",
                   "\n": b"\\n", "\r": b"\\r", "\t": b"\\t"}
        for char in value:
            if char in escapes:
                emit(escapes[char])
            elif ord(char) < 0x20:
                emit(("\\u%04x" % ord(char)).encode("ascii"))
            else:
                emit(char.encode("utf-8"))
        emit(b'"')

    stack = [("value", value, 1)]
    while stack:
        operation, current, depth = stack.pop()
        if operation == "emit":
            emit(current)
            continue
        budget._node(depth)
        if type(current) is str:
            string(current)
        elif current is None:
            emit(b"null")
        elif type(current) is bool:
            emit(b"true" if current else b"false")
        elif type(current) is int:
            emit(str(current).encode("ascii"))
        elif type(current) is _DraftList:
            emit(b"[")
            stack.append(("emit", b"]", depth))
            for index in range(len(current) - 1, -1, -1):
                if index < len(current) - 1:
                    stack.append(("emit", b",", depth))
                stack.append(("value", current[index], depth + 1))
        else:  # Only dict values produced by the strict parser reach this path.
            emit(b"{")
            stack.append(("emit", b"}", depth))
            keys = sorted(current)  # Unicode code points, not UTF-16 or locale.
            for index in range(len(keys) - 1, -1, -1):
                key = keys[index]
                if index < len(keys) - 1:
                    stack.append(("emit", b",", depth))
                stack.append(("value", current[key], depth + 1))
                stack.append(("emit", b":", depth))
                stack.append(("value", key, depth + 1))
    return bytes(output)


def parse_canonical_json(raw: bytes, policy: RepairPolicy, budget: RepairBudget) -> DraftJson:
    _context(policy, budget)
    with budget._lock:
        draft = parse_new_json(raw, policy, budget)
        if _canonical(draft.value, budget) != draft.raw:
            _fail("repair_noncanonical_json")
        return draft


parse_new_wire = parse_canonical_json


def _clone_new_value(value: Any, budget: RepairBudget):
    """Copy only caller-owned JSON values, with an explicit active-path stack."""
    wire_size = 0
    available = budget.policy.max_total_bytes - sum(
        budget._usage[field] for field in ("input_bytes", "output_bytes"))
    active, stack = set(), []

    def reserve(amount: int):
        nonlocal wire_size
        if (amount > budget.policy.max_document_bytes - wire_size
                or amount > available - wire_size):
            _fail("repair_over_budget")
        wire_size += amount

    def string(current: str):
        size = 0
        reserve(2)
        for char in current:
            cp = ord(char)
            if 0xD800 <= cp <= 0xDFFF:
                _fail("repair_invalid_unicode")
            length = _utf8_size(char)
            if length > budget.policy.max_string_bytes - size:
                _fail("repair_over_budget")
            budget._string(length)
            size += length
            reserve(2 if char in '"\\\b\f\n\r\t' else 6 if cp < 0x20 else length)
        return current

    def clone(current: Any, depth: int):
        budget._node(depth)
        kind = type(current)
        if current is None:
            reserve(4)
            return None
        if kind is bool:
            reserve(4 if current else 5)
            return current
        if kind in (int, float):
            number = u53(current)
            reserve(len(str(number)))  # At most sixteen U53 decimal digits.
            return number
        if kind is str:
            return string(current)
        if kind not in (dict, _DraftDict, list, _DraftList) or id(current) in active:
            _fail("repair_invalid_json")
        reserve(2)
        active.add(id(current))
        if kind in (list, _DraftList):
            result = _DraftList()
            stack.append([current, result, None, depth, len(current), 0])
        else:
            result = _DraftDict()
            stack.append([current, result, iter(dict.items(current)), depth, len(current), 0])
        return result

    result = clone(value, 1)
    while stack:
        source, target, iterator, depth, count, index = stack[-1]
        if len(source) != count:
            _fail("repair_invalid_json")
        if index == count:
            active.remove(id(source))
            stack.pop()
            continue
        stack[-1][5] += 1
        if index:
            reserve(1)
        if iterator is None:
            try:
                child = source[index]
            except IndexError:
                _fail("repair_invalid_json")
            list.append(target, clone(child, depth + 1))
        else:
            try:
                key, child = next(iterator)
            except (StopIteration, RuntimeError):
                _fail("repair_invalid_json")
            budget._node(depth + 1)
            if type(key) is not str:
                _fail("repair_invalid_json")
            string(key)
            reserve(1)
            dict.__setitem__(target, key, clone(child, depth + 1))
    return result


def build_new_wire(value: Any, policy: RepairPolicy, budget: RepairBudget) -> DraftJson:
    """Build canonical draft bytes from a bounded immutable JSON-value copy.

    No input bytes or signatures are fabricated. Validation/copy and canonical
    output each charge their real node/string traversal. Output size is checked
    incrementally before encoding; only actual encoding charges output bytes.
    Shared subtrees are copied per occurrence; cycles on the active path fail.
    This accepts local caller objects, not arbitrary objects received remotely.
    """
    _context(policy, budget)
    with budget._lock:
        copied = _clone_new_value(value, budget)
        return DraftJson(_canonical(copied, budget), copied)


@dataclass(frozen=True)
class RawRef:
    namespace: str
    key: str
    raw_sha256: str
    size: int

    def __post_init__(self):
        if (type(self.namespace) is not str or self.namespace not in ("meta", "object")
                or type(self.key) is not str or _HASH.fullmatch(self.key) is None
                or type(self.raw_sha256) is not str or _HASH.fullmatch(self.raw_sha256) is None
                or type(self.size) is not int or not 1 <= self.size <= U53_MAX):
            _fail("repair_invalid_ref")

    def as_dict(self) -> dict:
        return dict(namespace=self.namespace, key=self.key,
                    raw_sha256=self.raw_sha256, size=self.size)


def raw_ref(value: Any) -> RawRef:
    if type(value) is RawRef:
        return value
    if type(value) not in (dict, _DraftDict) or value.keys() != {"namespace", "key", "raw_sha256", "size"}:
        _fail("repair_invalid_ref")
    return RawRef(**value)


@dataclass(frozen=True)
class RawOriginal:
    ref: RawRef
    raw: bytes


class LocalRawResolver:
    """Finite in-memory exact-byte map, not a network or signature resolver.

    A key is an opaque lookup hash. It need not equal the raw SHA-256. A second
    original at the same namespace/key conflicts; an identical retry performs
    actual byte/hash work without charging a second retained entry.
    """

    __slots__ = ("__policy", "__budget", "__originals")

    def __init__(self, policy: RepairPolicy, budget: RepairBudget):
        _context(policy, budget)
        if hasattr(self, "_LocalRawResolver__originals"):
            _fail("repair_invalid_policy")
        object.__setattr__(self, "_LocalRawResolver__policy", policy)
        object.__setattr__(self, "_LocalRawResolver__budget", budget)
        object.__setattr__(self, "_LocalRawResolver__originals", {})

    def __setattr__(self, name, value):
        raise AttributeError("repair_resolver_immutable")

    def __delattr__(self, name):
        raise AttributeError("repair_resolver_immutable")

    @property
    def policy(self) -> RepairPolicy:
        return self.__policy

    @property
    def budget(self) -> RepairBudget:
        return self.__budget

    def put(self, namespace: str, key: str, raw: bytes) -> RawOriginal:
        with self.budget._lock:
            size = _raw_size(raw, self.policy)
            RawRef(namespace, key, "0" * 64, size)  # Closed identity before work.
            prior = self.__originals.get((namespace, key))
            if prior is None:
                self.budget._fits("entries", 1, self.policy.max_entries)
                self.budget._fits("retained_bytes", size, self.policy.max_retained_bytes)
            original = _snapshot(raw, self.policy, self.budget)
            size = len(original)
            if prior is None:
                self.budget._fits("retained_bytes", size, self.policy.max_retained_bytes)
            reference = RawRef(namespace, key, self.budget._hash(original), size)
            if prior is not None:
                if prior.ref != reference or not hmac.compare_digest(prior.raw, original):
                    _fail("repair_ref_conflict")
                return prior
            result = RawOriginal(reference, original)
            self.__originals[(namespace, key)] = result
            self.budget._retain(size)
            return result

    def resolve(self, reference: RawRef | dict) -> RawOriginal:
        with self.budget._lock:
            reference = raw_ref(reference)
            original = self.__originals.get((reference.namespace, reference.key))
            if original is None:
                _fail("repair_ref_missing")
            if reference.size != len(original.raw):
                _fail("repair_ref_mismatch")
            raw = _snapshot(original.raw, self.policy, self.budget)
            digest = self.budget._hash(raw)
            if not hmac.compare_digest(digest, reference.raw_sha256):
                _fail("repair_ref_mismatch")
            return original

    get = resolve


PACK_MAGIC = b"MVRP1\x00"
_PACK_PREFIX = 10
_PACK_HEADER = 40
_U32_MAX = 4294967295


@dataclass(frozen=True)
class PackEntry:
    raw_sha256: str
    size: int
    offset: int


@dataclass(frozen=True, slots=True)
class DraftPack:
    """Local byte integrity only; no historical closure or disclosure verdict.

    Offsets are derived by the parser/builder. Raw bytes and index are immutable.
    Extracting an entry preserves its separately supplied opaque parent locator;
    matching bytes alone do not prove ownership of that locator.
    """

    ref: RawRef
    raw: bytes
    entries: tuple[PackEntry, ...]
    _budget: RepairBudget

    def entry(self, index: int, document_ref: RawRef | dict) -> RawOriginal:
        with self._budget._lock:
            index = u53(index)
            if index >= len(self.entries):
                _fail("repair_invalid_pack")
            reference = raw_ref(document_ref)
            selected = self.entries[index]
            if (reference.size != selected.size
                    or reference.raw_sha256 != selected.raw_sha256):
                _fail("repair_ref_mismatch")
            # Charge before the physical output slice; no JSON reserialization.
            self._budget._bytes("output_bytes", selected.size)
            body = self.raw[selected.offset:selected.offset + selected.size]
            digest = self._budget._hash(body)
            if len(body) != reference.size or not hmac.compare_digest(digest, reference.raw_sha256):
                _fail("repair_ref_mismatch")
            return RawOriginal(reference, body)


def _pack_capacity(budget: RepairBudget, size: int, count: int):
    # A pack plus count derived index records share the resolver's holding cap.
    # Forty bytes per record is the fixed wire/index representation, not Python
    # heap size. Temporary buffers are additionally charged as input/output work.
    if not 1 <= count <= _U32_MAX:
        _fail("repair_invalid_pack")
    if size > budget.policy.max_document_bytes:
        _fail("repair_over_budget")
    budget._fits("entries", count + 1, budget.policy.max_entries)
    budget._fits("retained_bytes", size + _PACK_HEADER * count,
                 budget.policy.max_retained_bytes)


def _pack_hold(budget: RepairBudget, size: int, count: int):
    _pack_capacity(budget, size, count)
    budget._retain(size + _PACK_HEADER * count, count + 1)


def _pack_size(total: int, amount: int, policy: RepairPolicy) -> int:
    if amount > U53_MAX - total or amount > policy.max_document_bytes - total:
        _fail("repair_over_budget")
    return total + amount


def parse_raw_pack(raw: bytes, expected_pack_ref: RawRef | dict,
                   policy: RepairPolicy, budget: RepairBudget) -> DraftPack:
    """Validate full MVRP1 framing, actual hashes and derived index, locally.

    Legacy Signed and int64 bytes are deliberately not parsed here. New metadata
    still needs its own canonical/schema checks, followed by full authority and
    complete manifest-closure validation by the eventual repair consumer.
    """
    _context(policy, budget)
    with budget._lock:
        reference = raw_ref(expected_pack_ref)
        if reference.namespace != "meta" or reference.key != reference.raw_sha256:
            _fail("repair_ref_mismatch")
        if _raw_size(raw, policy) != reference.size:
            _fail("repair_ref_mismatch")
        # Inspect only the fixed header through a borrowed byte view before any
        # full snapshot or hash. Repeat against the frozen copy below.
        try:
            with memoryview(raw) as source, source.cast("B") as view:
                if len(view) < _PACK_PREFIX or view[:6] != PACK_MAGIC:
                    _fail("repair_invalid_pack")
                initial_count = int.from_bytes(view[6:10], "big")
                _pack_capacity(budget, len(view), initial_count)
                if initial_count > (len(view) - _PACK_PREFIX) // (_PACK_HEADER + 1):
                    _fail("repair_invalid_pack")
        except (TypeError, ValueError, BufferError) as error:
            if isinstance(error, RepairWireError):
                raise
            _fail("repair_invalid_bytes")
        original = _snapshot(raw, policy, budget)
        if len(original) != reference.size:
            _fail("repair_ref_mismatch")
        if len(original) < _PACK_PREFIX or original[:6] != PACK_MAGIC:
            _fail("repair_invalid_pack")
        count = int.from_bytes(original[6:10], "big")
        _pack_capacity(budget, len(original), count)
        # Every positive entry needs a complete header and at least one byte.
        if count > (len(original) - _PACK_PREFIX) // (_PACK_HEADER + 1):
            _fail("repair_invalid_pack")
        entries, offset, previous = [], _PACK_PREFIX, None
        for _ in range(count):
            budget._node(1)  # Before allocating each decoded index record.
            if len(original) - offset < _PACK_HEADER:
                _fail("repair_invalid_pack")
            size = int.from_bytes(original[offset:offset + 8], "big")
            digest = original[offset + 8:offset + _PACK_HEADER]
            offset += _PACK_HEADER
            if not 1 <= size <= U53_MAX or size > len(original) - offset:
                _fail("repair_invalid_pack")
            identity = (digest, size)
            if previous is not None and identity <= previous:
                _fail("repair_invalid_pack")
            if original[offset:offset + min(size, len(PACK_MAGIC))] == PACK_MAGIC:
                _fail("repair_invalid_pack")
            # A view avoids a second retained body copy while actually hashing.
            body = memoryview(original)[offset:offset + size]
            if not hmac.compare_digest(budget._hash(body), digest.hex()):
                _fail("repair_ref_mismatch")
            entries.append(PackEntry(digest.hex(), size, offset))
            offset += size
            previous = identity
        if offset != len(original):
            _fail("repair_invalid_pack")
        if not hmac.compare_digest(budget._hash(original), reference.raw_sha256):
            _fail("repair_ref_mismatch")
        _pack_hold(budget, len(original), count)
        return DraftPack(reference, original, tuple(entries), budget)


def build_raw_pack(raws: list[bytes] | tuple[bytes, ...], policy: RepairPolicy,
                   budget: RepairBudget) -> DraftPack:
    """Freeze originals and build the canonical byte pack without granting trust.

    Repeated identical inputs share one stored entry. Reading and hashing each
    input still consumes the same cumulative budget, including rejected work.
    """
    _context(policy, budget)
    with budget._lock:
        if type(raws) not in (list, tuple) or not 1 <= len(raws) <= _U32_MAX:
            _fail("repair_invalid_pack")
        count = len(raws)
        # Check count before copying the caller's list or creating an index.
        _pack_capacity(budget, _PACK_PREFIX, count)
        inputs = tuple(raws[:count])  # Bounded even if another thread appends.
        if len(inputs) != count or len(raws) != count:
            _fail("repair_invalid_pack")
        # Hold every mutable export before preflighting the batch. Snapshotting
        # each caller buffer separately later would permit a still-unexported
        # input to resize after the batch's holding capacity was checked.
        with ExitStack() as exports:
            fixed = []
            for raw in inputs:
                _raw_size(raw, policy)
                try:
                    fixed.append(raw if type(raw) is bytes else exports.enter_context(memoryview(raw)))
                except (ValueError, BufferError):
                    _fail("repair_invalid_bytes")
            total = _PACK_PREFIX
            for raw in fixed:
                size = _raw_size(raw, policy)
                if size == 0:
                    _fail("repair_invalid_pack")
                total = _pack_size(total, _PACK_HEADER + size, policy)
            _pack_capacity(budget, total, count)
            unique = {}
            for raw in fixed:
                budget._node(1)
                original = _snapshot(raw, policy, budget)
                if not original or original.startswith(PACK_MAGIC):
                    _fail("repair_invalid_pack")
                digest = budget._hash(original)
                identity = (digest, len(original))
                prior = unique.get(identity)
                if prior is not None and not hmac.compare_digest(prior, original):
                    _fail("repair_ref_conflict")
                unique[identity] = original
            total = _PACK_PREFIX
            for original in unique.values():
                total = _pack_size(total, _PACK_HEADER + len(original), policy)
            _pack_capacity(budget, total, len(unique))
            # Charge the allocated construction buffer and its final immutable copy.
            budget._bytes("output_bytes", total)
            output = bytearray(total)
            output[:6] = PACK_MAGIC
            output[6:10] = len(unique).to_bytes(4, "big")
            entries, offset = [], _PACK_PREFIX
            for (digest, size), original in sorted(unique.items()):
                output[offset:offset + 8] = size.to_bytes(8, "big")
                output[offset + 8:offset + _PACK_HEADER] = bytes.fromhex(digest)
                offset += _PACK_HEADER
                output[offset:offset + size] = original
                entries.append(PackEntry(digest, size, offset))
                offset += size
            budget._bytes("output_bytes", total)
            packed = bytes(output)
            digest = budget._hash(packed)
            reference = RawRef("meta", digest, digest, total)
            _pack_hold(budget, total, len(entries))
            return DraftPack(reference, packed, tuple(entries), budget)
