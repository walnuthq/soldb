"""Unit tests for soldb.utils.colors."""

import pytest

from soldb.utils.colors import (
    Colors,
    address,
    blue,
    bold,
    bullet_point,
    cyan,
    dim,
    error,
    function_name,
    gas_value,
    green,
    highlight,
    info,
    magenta,
    number,
    opcode,
    pc_value,
    red,
    source_line,
    stack_item,
    success,
    underline,
    warning,
    yellow,
)


def _snapshot_color_attrs():
    return {a: getattr(Colors, a) for a in dir(Colors) if a.isupper() and not a.startswith("_")}


def _restore_color_attrs(snapshot):
    for attr, value in snapshot.items():
        setattr(Colors, attr, value)


def test_basic_color_helpers_wrap_input():
    helpers = [
        red, green, yellow, blue, magenta, cyan,
        bold, dim, underline,
        error, success, warning, info, highlight,
        opcode, address, source_line, function_name,
    ]
    for helper in helpers:
        out = helper("hello")
        assert "hello" in out
        # When colors are active each helper appends RESET; when disabled the
        # codes are empty and the output is the bare input. Either is valid.
        assert out == "hello" or out.endswith(Colors.RESET)


def test_number_helper_wraps_input():
    # number() formats text but is documented for numeric strings; it just wraps.
    assert "42" in number("42")


def test_pc_and_gas_values_are_zero_padded():
    # pc_value pads to width 4, gas_value to width 7.
    assert "  42" in pc_value(42)
    assert "      7" in gas_value(7)


def test_stack_item_includes_index_and_value():
    out = stack_item(3, "0xabc")
    assert "[3]" in out
    assert "0xabc" in out


def test_bullet_point_includes_text_and_dash():
    out = bullet_point("thing")
    assert "thing" in out
    assert "-" in out


def test_disable_zeroes_every_color_code_and_helpers_become_passthrough():
    snapshot = _snapshot_color_attrs()
    try:
        Colors.disable()
        for attr in snapshot:
            assert getattr(Colors, attr) == ""
        # With every code blanked the helpers must return the bare input.
        assert red("xyz") == "xyz"
        assert highlight("h") == "h"
        assert bullet_point("b") == "  - b"
    finally:
        _restore_color_attrs(snapshot)


def test_enable_currently_raises_type_error():
    # `Colors.enable()` calls `cls.__init__()` which dispatches to
    # `object.__init__` and raises TypeError because no instance is passed.
    # Captured here so a future fix flips this assertion intentionally.
    with pytest.raises(TypeError):
        Colors.enable()
