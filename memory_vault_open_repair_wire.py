"""Bounded local draft parsing and exact original-byte references for repair.

No authority, signature, resource or custody is accepted here. A DraftJson is
only parsed data; new repair consumers must use parse_new_wire and then their
own closed schema and complete authority verifier. Historical originals use the
byte resolver, never the new JSON parser or a canonical reserialization.
"""
from __future__ import annotations

from dataclasses import dataclass, fields as dataclass_fields
import hashlib
import hmac
import re
from threading import RLock
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


@dataclass(frozen=True)
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
    actual canonical output. nodes/string_bytes include the second canonical
    traversal. retained_bytes/entries describe only this resolver's holdings,
    not all interpreter heap allocations. No signature verifier is called.
    One private reentrant lock serializes whole public operations sharing this
    budget, including resolver holdings. This is not a database writer lock.
    """

    def __init__(self, policy: RepairPolicy):
        if type(policy) is not RepairPolicy:
            _fail("repair_invalid_policy")
        self._policy = policy
        self._lock = RLock()
        self._usage = dict(input_bytes=0, output_bytes=0, nodes=0,
                           string_bytes=0, max_depth=0, hash_bytes=0, hashes=0,
                           entries=0, retained_bytes=0, signature_checks=0)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return self._usage.copy()

    @property
    def policy(self) -> RepairPolicy:
        return self._policy

    def _fits(self, field: str, amount: int, limit: int):
        if amount > limit - self._usage[field]:
            _fail("repair_over_budget")

    def _bytes(self, field: str, amount: int):
        total = self._usage["input_bytes"] + self._usage["output_bytes"]
        if amount > self.policy.max_total_bytes - total:
            _fail("repair_over_budget")
        self._usage[field] += amount

    def _node(self, depth: int):
        if depth > self.policy.max_depth:
            _fail("repair_over_budget")
        self._fits("nodes", 1, self.policy.max_nodes)
        self._usage["nodes"] += 1
        self._usage["max_depth"] = max(self._usage["max_depth"], depth)

    def _string(self, size: int):
        if size > self.policy.max_string_bytes:
            _fail("repair_over_budget")
        if size > U53_MAX - self._usage["string_bytes"]:
            _fail("repair_over_budget")
        self._usage["string_bytes"] += size

    def _hash(self, raw: bytes) -> str:
        self._fits("hashes", 1, self.policy.max_hashes)
        self._fits("hash_bytes", len(raw), self.policy.max_hash_bytes)
        result = hashlib.sha256(raw).hexdigest()
        self._usage["hashes"] += 1
        self._usage["hash_bytes"] += len(raw)
        return result


def _context(policy: RepairPolicy, budget: RepairBudget):
    if (type(policy) is not RepairPolicy or type(budget) is not RepairBudget
            or budget.policy != policy):
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

    def __init__(self, policy: RepairPolicy, budget: RepairBudget):
        _context(policy, budget)
        self._policy, self._budget = policy, budget
        self._originals: dict[tuple[str, str], RawOriginal] = {}

    @property
    def policy(self) -> RepairPolicy:
        return self._policy

    @property
    def budget(self) -> RepairBudget:
        return self._budget

    def put(self, namespace: str, key: str, raw: bytes) -> RawOriginal:
        with self.budget._lock:
            size = _raw_size(raw, self.policy)
            RawRef(namespace, key, "0" * 64, size)  # Closed identity before work.
            prior = self._originals.get((namespace, key))
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
            self._originals[(namespace, key)] = result
            self.budget._usage["entries"] += 1
            self.budget._usage["retained_bytes"] += size
            return result

    def resolve(self, reference: RawRef | dict) -> RawOriginal:
        with self.budget._lock:
            reference = raw_ref(reference)
            original = self._originals.get((reference.namespace, reference.key))
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
