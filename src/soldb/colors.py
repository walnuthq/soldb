"""
Color utilities for the SolDB EVM Debugger

Provides ANSI color codes for terminal output.
"""

import os
import sys

# Check if colors are supported
SUPPORTS_COLOR = (
    hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and
    os.environ.get('TERM') != 'dumb' and
    not os.environ.get('NO_COLOR')
)

class Colors:
    """ANSI color codes for terminal output."""
    
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'
    
    # Reset
    RESET = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Disable all colors."""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')
    
    @classmethod
    def enable(cls):
        """Re-enable colors."""
        cls.__init__()


# Disable colors if not supported
if not SUPPORTS_COLOR:
    Colors.disable()


# Convenience functions
def red(text: str) -> str:
    """Return text in red."""
    return f"{Colors.RED}{text}{Colors.RESET}"

def green(text: str) -> str:
    """Return text in green."""
    return f"{Colors.GREEN}{text}{Colors.RESET}"

def yellow(text: str) -> str:
    """Return text in yellow."""
    return f"{Colors.YELLOW}{text}{Colors.RESET}"

def blue(text: str) -> str:
    """Return text in blue."""
    return f"{Colors.BLUE}{text}{Colors.RESET}"

def magenta(text: str) -> str:
    """Return text in magenta."""
    return f"{Colors.MAGENTA}{text}{Colors.RESET}"

def cyan(text: str) -> str:
    """Return text in cyan."""
    return f"{Colors.CYAN}{text}{Colors.RESET}"

def bold(text: str) -> str:
    """Return text in bold."""
    return f"{Colors.BOLD}{text}{Colors.RESET}"

def dim(text: str) -> str:
    """Return text dimmed."""
    return f"{Colors.DIM}{text}{Colors.RESET}"

def underline(text: str) -> str:
    """Return text underlined."""
    return f"{Colors.UNDERLINE}{text}{Colors.RESET}"


# Semantic color functions for debugging
def error(text: str) -> str:
    """Format error text."""
    return f"{Colors.BRIGHT_RED}{text}{Colors.RESET}"

def success(text: str) -> str:
    """Format success text."""
    return f"{Colors.BRIGHT_GREEN}{text}{Colors.RESET}"

def warning(text: str) -> str:
    """Format warning text."""
    return f"{Colors.BRIGHT_YELLOW}{text}{Colors.RESET}"

def info(text: str) -> str:
    """Format info text."""
    return f"{Colors.BRIGHT_CYAN}{text}{Colors.RESET}"

def highlight(text: str) -> str:
    """Highlight important text."""
    return f"{Colors.BOLD}{Colors.BRIGHT_WHITE}{text}{Colors.RESET}"

def opcode(text: str) -> str:
    """Format EVM opcode."""
    return f"{Colors.BRIGHT_BLUE}{text}{Colors.RESET}"

def address(text: str) -> str:
    """Format Ethereum address."""
    return f"{Colors.BRIGHT_MAGENTA}{text}{Colors.RESET}"

def number(text: str) -> str:
    """Format numbers."""
    return f"{Colors.BRIGHT_YELLOW}{text}{Colors.RESET}"

def source_line(text: str) -> str:
    """Format source code line."""
    return f"{Colors.GREEN}{text}{Colors.RESET}"

def stack_item(index: int, value: str) -> str:
    """Format stack item with index."""
    return f"{Colors.DIM}[{index}]{Colors.RESET} {Colors.BRIGHT_CYAN}{value}{Colors.RESET}"

def pc_value(pc: int) -> str:
    """Format program counter."""
    return f"{Colors.BRIGHT_YELLOW}{pc:4d}{Colors.RESET}"

def gas_value(gas: int) -> str:
    """Format gas value."""
    return f"{Colors.BRIGHT_GREEN}{gas:7d}{Colors.RESET}"

def function_name(name: str) -> str:
    """Format function name."""
    return f"{Colors.BRIGHT_MAGENTA}{name}{Colors.RESET}"
