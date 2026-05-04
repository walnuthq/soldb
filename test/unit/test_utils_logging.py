"""Unit tests for soldb.utils.logging."""

import logging
from typing import List

from soldb.utils import logging as soldb_logging
from soldb.utils.colors import Colors
from soldb.utils.logging import (
    ColoredFormatter,
    SoldbLogger,
    TRACE,
    get_logger,
    log_debug,
    log_error,
    log_info,
    log_trace,
    log_warning,
    setup_logging,
)


def test_trace_level_is_below_debug_and_named():
    assert TRACE < logging.DEBUG
    assert logging.getLevelName(TRACE) == "TRACE"


def test_colored_formatter_wraps_levelname_when_colors_enabled():
    formatter = ColoredFormatter(fmt="%(levelname)s:%(message)s", use_colors=True)
    record = logging.LogRecord(
        name="t", level=logging.ERROR, pathname=__file__, lineno=1,
        msg="boom", args=(), exc_info=None,
    )
    formatted = formatter.format(record)
    # ERROR should be bracketed by the BRIGHT_RED code and the RESET code.
    assert Colors.BRIGHT_RED in formatted
    assert Colors.RESET in formatted
    assert "boom" in formatted


def test_colored_formatter_skips_codes_when_colors_disabled():
    formatter = ColoredFormatter(fmt="%(levelname)s:%(message)s", use_colors=False)
    record = logging.LogRecord(
        name="t", level=logging.ERROR, pathname=__file__, lineno=1,
        msg="boom", args=(), exc_info=None,
    )
    formatted = formatter.format(record)
    assert formatted == "ERROR:boom"


def test_colored_formatter_unknown_level_uses_no_color():
    # An unknown level number falls through the LEVEL_COLORS lookup and must
    # not crash; the levelname survives untouched.
    formatter = ColoredFormatter(fmt="%(levelname)s", use_colors=True)
    record = logging.LogRecord(
        name="t", level=999, pathname=__file__, lineno=1,
        msg="x", args=(), exc_info=None,
    )
    formatted = formatter.format(record)
    assert "Level 999" in formatted


def test_setup_logging_quiet_attaches_no_console_handler():
    logger = setup_logging(quiet=True)
    try:
        assert logger.name == "soldb"
        assert logger.handlers == []
        assert logger.propagate is False
    finally:
        logger.handlers.clear()


def test_setup_logging_verbose_uses_trace_and_attaches_console():
    logger = setup_logging(verbose=True)
    try:
        assert logger.level == TRACE
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    finally:
        logger.handlers.clear()


def test_setup_logging_debug_overrides_default_level():
    logger = setup_logging(debug=True)
    try:
        assert logger.level == logging.DEBUG
    finally:
        logger.handlers.clear()


def test_setup_logging_writes_to_log_file(tmp_path):
    log_path = tmp_path / "soldb.log"
    logger = setup_logging(quiet=True, log_file=str(log_path))
    try:
        logger.error("disk on fire")
        for handler in logger.handlers:
            handler.flush()
        contents = log_path.read_text()
        assert "disk on fire" in contents
        assert "ERROR" in contents
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers.clear()


def test_get_logger_returns_root_or_child():
    assert get_logger().name == "soldb"
    assert get_logger("tracer").name == "soldb.tracer"


class _ListHandler(logging.Handler):
    """Capture records on the target logger directly to bypass propagation."""

    def __init__(self):
        super().__init__(level=TRACE)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _attach_capture(logger: logging.Logger) -> _ListHandler:
    handler = _ListHandler()
    logger.addHandler(handler)
    return handler


def test_soldb_logger_trace_emits_when_enabled():
    logger = get_logger("trace-test")
    assert isinstance(logger, SoldbLogger)
    logger.setLevel(TRACE)
    handler = _attach_capture(logger)
    try:
        logger.trace("very detailed")
        assert any("very detailed" in r.getMessage() for r in handler.records)
    finally:
        logger.removeHandler(handler)


def test_soldb_logger_trace_skips_when_disabled():
    logger = get_logger("trace-skip")
    logger.setLevel(logging.CRITICAL)
    # Returns silently — no handler invoked. The point is that the call is a no-op.
    assert logger.trace("ignored") is None


def test_convenience_log_functions_route_to_module_logger():
    soldb_root = get_logger()
    soldb_root.setLevel(TRACE)
    handler = _attach_capture(soldb_root)
    try:
        log_debug("d")
        log_info("i")
        log_warning("w")
        log_error("e")
        log_trace("t")
        messages = {r.getMessage() for r in handler.records}
        assert {"d", "i", "w", "e", "t"}.issubset(messages)
    finally:
        soldb_root.removeHandler(handler)


def test_log_trace_falls_back_to_log_when_logger_missing_trace(monkeypatch):
    # Swap the module logger for a plain logger with no `trace` attribute,
    # exercising the fallback path in log_trace.
    plain = logging.getLogger("soldb-plain")
    plain.setLevel(TRACE)
    handler = _attach_capture(plain)
    monkeypatch.setattr(soldb_logging, "logger", plain)
    try:
        soldb_logging.log_trace("fallback")
        assert any("fallback" in r.getMessage() for r in handler.records)
    finally:
        plain.removeHandler(handler)
