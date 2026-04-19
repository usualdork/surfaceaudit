"""DSL evaluator for v2 rule engine boolean expressions.

Grammar::

    expression  := or_expr
    or_expr     := and_expr ("or" and_expr)*
    and_expr    := comparison ("and" comparison)*
    comparison  := atom (("==" | "!=" | ">" | "<" | ">=" | "<=" | "contains") atom)?
    atom        := "(" expression ")" | STRING | NUMBER | FIELD_REF

Field references are resolved from :class:`AssetContext`.  Null fields
become ``""`` for string operations and ``0`` for numeric operations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from surfaceaudit.rules.v2.schema import AssetContext


class DSLSyntaxError(Exception):
    """Raised when a DSL expression cannot be parsed."""


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

# Token types
_TK_STRING = "STRING"
_TK_NUMBER = "NUMBER"
_TK_IDENT = "IDENT"
_TK_OP = "OP"
_TK_LPAREN = "LPAREN"
_TK_RPAREN = "RPAREN"
_TK_EOF = "EOF"


_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<string>'[^']*')       # single-quoted string
      | (?P<number>-?\d+(?:\.\d+)?)  # integer or float
      | (?P<op>==|!=|>=|<=|>|<|contains)  # comparison operators
      | (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)  # identifiers / keywords
    )\s*
    """,
    re.VERBOSE,
)


def _tokenise(expr: str) -> list[tuple[str, str]]:
    """Convert *expr* into a flat list of ``(type, value)`` tokens."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expr):
        # skip leading whitespace
        while pos < len(expr) and expr[pos] in " \t":
            pos += 1
        if pos >= len(expr):
            break
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.start() != pos:
            raise DSLSyntaxError(
                f"Unexpected character at position {pos}: {expr[pos:]!r}"
            )
        if m.group("string") is not None:
            # strip surrounding quotes
            tokens.append((_TK_STRING, m.group("string")[1:-1]))
        elif m.group("number") is not None:
            tokens.append((_TK_NUMBER, m.group("number")))
        elif m.group("op") is not None:
            tokens.append((_TK_OP, m.group("op")))
        elif m.group("lparen") is not None:
            tokens.append((_TK_LPAREN, "("))
        elif m.group("rparen") is not None:
            tokens.append((_TK_RPAREN, ")"))
        elif m.group("ident") is not None:
            tokens.append((_TK_IDENT, m.group("ident")))
        pos = m.end()
    tokens.append((_TK_EOF, ""))
    return tokens


# ---------------------------------------------------------------------------
# Recursive-descent parser / evaluator
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive-descent parser that evaluates a DSL expression in one pass."""

    def __init__(self, tokens: list[tuple[str, str]], context: "AssetContext") -> None:
        self._tokens = tokens
        self._pos = 0
        self._context = context

    # -- helpers -------------------------------------------------------------

    def _peek(self) -> tuple[str, str]:
        return self._tokens[self._pos]

    def _advance(self) -> tuple[str, str]:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, tk_type: str, value: str | None = None) -> tuple[str, str]:
        tok = self._peek()
        if tok[0] != tk_type or (value is not None and tok[1] != value):
            expected = value if value else tk_type
            raise DSLSyntaxError(
                f"Expected {expected}, got {tok[1]!r}"
            )
        return self._advance()

    # -- grammar rules -------------------------------------------------------

    def parse(self) -> bool:
        """Parse the full expression and return its boolean result."""
        result = self._or_expr()
        if self._peek()[0] != _TK_EOF:
            raise DSLSyntaxError(
                f"Unexpected token after expression: {self._peek()[1]!r}"
            )
        return bool(result)

    def _or_expr(self) -> object:
        """or_expr := and_expr ("or" and_expr)*"""
        left = self._and_expr()
        while self._peek() == (_TK_IDENT, "or"):
            self._advance()
            right = self._and_expr()
            left = _to_bool(left) or _to_bool(right)
        return left

    def _and_expr(self) -> object:
        """and_expr := comparison ("and" comparison)*"""
        left = self._comparison()
        while self._peek() == (_TK_IDENT, "and"):
            self._advance()
            right = self._comparison()
            left = _to_bool(left) and _to_bool(right)
        return left

    def _comparison(self) -> object:
        """comparison := atom (("==" | "!=" | ">" | "<" | ">=" | "<=" | "contains") atom)?"""
        left = self._atom()
        tok_type, tok_val = self._peek()
        if tok_type == _TK_OP:
            self._advance()
            right = self._atom()
            return _apply_op(tok_val, left, right)
        return left

    def _atom(self) -> object:
        """atom := "(" expression ")" | STRING | NUMBER | FIELD_REF"""
        tok_type, tok_val = self._peek()

        if tok_type == _TK_LPAREN:
            self._advance()
            result = self._or_expr()
            self._expect(_TK_RPAREN)
            return result

        if tok_type == _TK_STRING:
            self._advance()
            return tok_val

        if tok_type == _TK_NUMBER:
            self._advance()
            if "." in tok_val:
                return float(tok_val)
            return int(tok_val)

        if tok_type == _TK_IDENT:
            # keywords "and", "or" are not valid atoms
            if tok_val in ("and", "or", "contains"):
                raise DSLSyntaxError(
                    f"Unexpected keyword {tok_val!r} in atom position"
                )
            self._advance()
            return self._resolve_field(tok_val)

        raise DSLSyntaxError(
            f"Unexpected token {tok_val!r} (type={tok_type})"
        )

    def _resolve_field(self, name: str) -> object:
        """Resolve a field reference from the asset context."""
        return self._context.get_field(name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_for_compare(left: object, right: object) -> tuple[object, object]:
    """Coerce *left* and *right* so they can be compared.

    * If either side is numeric (int/float), coerce both to numbers
      (null → 0).
    * Otherwise coerce both to strings (null → ``""``).
    """
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return _to_number(left), _to_number(right)
    return _to_string(left), _to_string(right)


def _to_number(val: object) -> int | float:
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        try:
            if "." in val:
                return float(val)
            return int(val)
        except (ValueError, TypeError):
            return 0
    return 0


def _to_string(val: object) -> str:
    if val is None:
        return ""
    return str(val)


def _to_bool(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    if isinstance(val, str):
        return val != ""
    if isinstance(val, (int, float)):
        return val != 0
    return bool(val)


def _apply_op(op: str, left: object, right: object) -> bool:
    """Apply a comparison operator to two values."""
    if op == "contains":
        return _to_string(right).lower() in _to_string(left).lower()

    left_c, right_c = _coerce_for_compare(left, right)

    if op == "==":
        return left_c == right_c
    if op == "!=":
        return left_c != right_c
    if op == ">":
        return left_c > right_c  # type: ignore[operator]
    if op == "<":
        return left_c < right_c  # type: ignore[operator]
    if op == ">=":
        return left_c >= right_c  # type: ignore[operator]
    if op == "<=":
        return left_c <= right_c  # type: ignore[operator]

    raise DSLSyntaxError(f"Unknown operator: {op!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class DSLEvaluator:
    """Evaluate a DSL expression against an :class:`AssetContext`."""

    def __init__(self, context: "AssetContext") -> None:
        self._context = context

    def evaluate(self, expression: str) -> bool:
        """Parse and evaluate *expression*, returning a boolean result."""
        tokens = _tokenise(expression)
        parser = _Parser(tokens, self._context)
        return parser.parse()


def validate_dsl_syntax(expression: str) -> None:
    """Validate that *expression* is syntactically correct.

    Raises :class:`DSLSyntaxError` on failure.  This is used by the
    rule validator at load time — it evaluates against a dummy context
    so that field resolution always succeeds.
    """
    from surfaceaudit.rules.v2.schema import AssetContext

    # Build a dummy context where every field returns a neutral value.
    dummy = AssetContext()
    tokens = _tokenise(expression)
    parser = _Parser(tokens, dummy)
    parser.parse()


@dataclass
class DSLMatcher:
    """Matcher that evaluates a DSL boolean expression."""

    expression: str

    def matches(self, context: "AssetContext") -> bool:
        """Evaluate the DSL expression against *context*."""
        evaluator = DSLEvaluator(context)
        return evaluator.evaluate(self.expression)
