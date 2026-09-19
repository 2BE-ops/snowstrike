"""Safe expression evaluator for flow conditions and when clauses.

Uses Python's ast module to parse expressions into an AST, then walks only
a safe subset of node types.  No eval()/exec()/import allowed.
"""

from __future__ import annotations

import ast
import operator
import re
from typing import Any

# Operators allowed in comparisons
_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

_BOOL_OPS = {
    ast.And: all,
    ast.Or: any,
}

_UNARY_OPS = {
    ast.Not: operator.not_,
    ast.USub: operator.neg,
}

# AST node types we permit
_SAFE_NODES = frozenset({
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.Compare,
    ast.Constant, ast.Name, ast.Attribute, ast.Subscript,
    ast.Load, ast.And, ast.Or, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Is, ast.IsNot, ast.In, ast.NotIn,
    ast.List, ast.Tuple, ast.Slice,
    ast.BinOp, ast.Add, ast.Sub,
    ast.IfExp,
})

# Pre-processing patterns for DSL sugar
_IS_EMPTY_RE = re.compile(r"(\S+)\s+is\s+empty")
_IS_NOT_EMPTY_RE = re.compile(r"(\S+)\s+is\s+not\s+empty")


class ConditionError(Exception):
    """Raised when a condition expression is invalid or unsafe."""


class ConditionEvaluator:
    """Evaluate safe boolean expressions against flow context."""

    def evaluate(self, expression: str, context: dict) -> bool:
        """Parse and evaluate *expression*.  Returns a boolean."""
        expr = self._preprocess(expression)
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as exc:
            raise ConditionError(f"Syntax error in expression: {exc}") from exc
        self._validate_ast(tree)
        result = self._eval_node(tree.body, context)
        return bool(result)

    # ------------------------------------------------------------------
    # Pre-processing
    # ------------------------------------------------------------------

    @staticmethod
    def _preprocess(expression: str) -> str:
        """Rewrite DSL sugar into valid Python expressions."""
        expr = expression
        # "X is not empty" -> "(X is not None and X != '' and X != [])"
        expr = _IS_NOT_EMPTY_RE.sub(
            r"(\1 is not None and \1 != '' and \1 != [])", expr
        )
        # "X is empty" -> "(X is None or X == '' or X == [])"
        expr = _IS_EMPTY_RE.sub(
            r"(\1 is None or \1 == '' or \1 == [])", expr
        )
        # Normalize true/false literals
        expr = re.sub(r"\btrue\b", "True", expr)
        expr = re.sub(r"\bfalse\b", "False", expr)
        expr = re.sub(r"\bnull\b", "None", expr)
        return expr

    # ------------------------------------------------------------------
    # AST validation
    # ------------------------------------------------------------------

    def _validate_ast(self, node: ast.AST) -> None:
        """Walk AST and reject disallowed node types."""
        for child in ast.walk(node):
            if type(child) not in _SAFE_NODES:
                raise ConditionError(
                    f"Disallowed expression node: {type(child).__name__}"
                )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _eval_node(self, node: ast.AST, ctx: dict) -> Any:
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self._resolve_name(node.id, ctx)

        if isinstance(node, ast.Attribute):
            obj = self._eval_node(node.value, ctx)
            if isinstance(obj, dict):
                return obj.get(node.attr)
            return getattr(obj, node.attr, None)

        if isinstance(node, ast.Subscript):
            obj = self._eval_node(node.value, ctx)
            idx = self._eval_node(node.slice, ctx)
            try:
                return obj[idx]
            except (KeyError, IndexError, TypeError):
                return None

        if isinstance(node, ast.BoolOp):
            op_fn = _BOOL_OPS.get(type(node.op))
            if op_fn is None:
                raise ConditionError(f"Unsupported bool op: {type(node.op).__name__}")
            values = [self._eval_node(v, ctx) for v in node.values]
            return op_fn(values)

        if isinstance(node, ast.UnaryOp):
            op_fn = _UNARY_OPS.get(type(node.op))
            if op_fn is None:
                raise ConditionError(f"Unsupported unary op: {type(node.op).__name__}")
            return op_fn(self._eval_node(node.operand, ctx))

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, ctx)
            for op_node, comparator in zip(node.ops, node.comparators):
                right = self._eval_node(comparator, ctx)
                op_fn = _CMP_OPS.get(type(op_node))
                if op_fn is None:
                    raise ConditionError(
                        f"Unsupported comparison: {type(op_node).__name__}"
                    )
                try:
                    if not op_fn(left, right):
                        return False
                except TypeError:
                    return False
                left = right
            return True

        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left, ctx)
            right = self._eval_node(node.right, ctx)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            raise ConditionError(f"Unsupported binary op: {type(node.op).__name__}")

        if isinstance(node, ast.IfExp):
            if self._eval_node(node.test, ctx):
                return self._eval_node(node.body, ctx)
            return self._eval_node(node.orelse, ctx)

        if isinstance(node, (ast.List, ast.Tuple)):
            return [self._eval_node(e, ctx) for e in node.elts]

        raise ConditionError(f"Cannot evaluate node: {type(node).__name__}")

    # ------------------------------------------------------------------
    # Name resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_name(name: str, ctx: dict) -> Any:
        """Resolve a top-level name from context.

        Names like ``steps`` or ``inputs`` are looked up as keys in *ctx*.
        Python builtins True/False/None are returned directly.
        """
        if name == "True":
            return True
        if name == "False":
            return False
        if name == "None":
            return None
        return ctx.get(name)
