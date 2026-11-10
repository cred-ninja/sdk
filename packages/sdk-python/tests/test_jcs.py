"""Cred Python SDK — RFC 8785 (JCS) serialization tests."""

import json
import struct
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest

from cred import CanonicalJsonError, canonical_json

VECTORS = json.loads((Path(__file__).parent / "jcs_vectors.json").read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=[str(i) for i in range(len(VECTORS))])
def test_matches_typescript_reference(vector):
    assert canonical_json(vector["input"]) == vector["expected"]


# RFC 8785 Appendix B: IEEE 754 bit patterns and their serialization.
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,expected", APPENDIX_B)
def test_rfc8785_appendix_b_numbers(bits, expected):
    assert canonical_json(struct.unpack(">d", bytes.fromhex(bits))[0]) == expected


def test_rfc8785_section_3_2_3_sample():
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "€$\x0f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }
    assert canonical_json(value) == (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )


def test_keys_sort_by_utf16_code_units():
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+E000 in
    # UTF-16 although its code point is larger.
    assert canonical_json({"": 1, "\U0001F600": 2, "a": 3}) == '{"a":3,"\U0001F600":2,"":1}'


def test_string_escapes():
    assert canonical_json("\b\f\n\r\t\x00\x1f\x7f ") == '"\\b\\f\\n\\r\\t\\u0000\\u001f\x7f "'


def test_bool_is_not_an_int():
    assert canonical_json([True, False, 1, 0]) == "[true,false,1,0]"


def test_safe_integer_bounds():
    assert canonical_json(2**53 - 1) == "9007199254740991"
    assert canonical_json(-(2**53 - 1)) == "-9007199254740991"
    for value in (2**53, -(2**53), 10**21):
        with pytest.raises(CanonicalJsonError):
            canonical_json(value)


def test_negative_zero():
    assert canonical_json(-0.0) == "0"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite(value):
    with pytest.raises(CanonicalJsonError) as exc_info:
        canonical_json(value)
    assert exc_info.value.code == "non_finite"


@pytest.mark.parametrize("value", ["\ud800", "a\udc00b", {"\ud83d": 1}])
def test_rejects_lone_surrogates(value):
    with pytest.raises(CanonicalJsonError):
        canonical_json(value)


@pytest.mark.parametrize("value", [b"bytes", {1: "a"}, {None: 1}, {1, 2}, Decimal("1.5"), Fraction(1, 3), object()])
def test_rejects_non_json_types(value):
    with pytest.raises(CanonicalJsonError):
        canonical_json(value)


def test_is_a_value_error():
    assert issubclass(CanonicalJsonError, ValueError)
