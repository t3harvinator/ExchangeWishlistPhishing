#!/usr/bin/env python3
"""Constant-fold the arithmetic string builders used by the captured JXA.

This intentionally does not execute JavaScript.  It recognizes only the
sample's numeric-array -> String.fromCharCode map idiom and evaluates its
integer arithmetic with a small allow-listed expression evaluator.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path


class UnsafeExpression(ValueError):
    pass


def eval_int(text: str, env: dict[str, int]) -> int:
    tree = ast.parse(text.strip(), mode="eval")

    def walk(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Invert)):
            value = walk(node.operand)
            if isinstance(node.op, ast.UAdd):
                return value
            if isinstance(node.op, ast.USub):
                return -value
            return ~value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op,
            (ast.Add, ast.Sub, ast.Mult, ast.Mod, ast.BitXor, ast.BitAnd, ast.BitOr,
             ast.LShift, ast.RShift, ast.FloorDiv),
        ):
            left, right = walk(node.left), walk(node.right)
            if isinstance(node.op, ast.Add): return left + right
            if isinstance(node.op, ast.Sub): return left - right
            if isinstance(node.op, ast.Mult): return left * right
            if isinstance(node.op, ast.Mod): return left % right
            if isinstance(node.op, ast.BitXor): return left ^ right
            if isinstance(node.op, ast.BitAnd): return left & right
            if isinstance(node.op, ast.BitOr): return left | right
            if isinstance(node.op, ast.LShift): return left << right
            if isinstance(node.op, ast.RShift): return left >> right
            if isinstance(node.op, ast.FloorDiv): return left // right
        raise UnsafeExpression(ast.dump(node))

    return walk(tree)


def split_top(text: str, delimiter: str = ",") -> list[str]:
    result, start = [], 0
    stack: list[str] = []
    quote = None
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for i, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif char == delimiter and not stack:
            result.append(text[start:i].strip())
            start = i + 1
    result.append(text[start:].strip())
    return result


def matching(text: str, start: int, opening: str, closing: str) -> int:
    depth, quote, escaped = 0, None, False
    for i in range(start, len(text)):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unmatched {opening} at {start}")


def matching_back(text: str, end: int, opening: str, closing: str) -> int:
    depth, quote, escaped = 0, None, False
    for i in range(end, -1, -1):
        char = text[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == closing:
            depth += 1
        elif char == opening:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unmatched {closing} at {end}")


def decode_property(expr: str) -> str | None:
    # Property expressions here are concatenations of quoted ASCII pieces.
    pieces = re.findall(r"['\"]([^'\"]*)['\"]", expr)
    residue = re.sub(r"['\"][^'\"]*['\"]|[+\s]", "", expr)
    return "".join(pieces) if pieces and not residue else None


def parse_array(text: str, env_arrays: dict[str, list[int]] | None = None) -> list[int]:
    env_arrays = env_arrays or {}
    body = text.strip()[1:-1]
    if not body.strip():
        return []
    return [eval_int(item, {}) for item in split_top(body)]


def decode_map_at(source: str, marker: int, arrays: dict[str, list[int]] | None = None):
    arrays = arrays or {}
    array_end = marker - 1
    if array_end < 0 or source[array_end] != "]":
        return None
    array_start = matching_back(source, array_end, "[", "]")
    values = parse_array(source[array_start:array_end + 1])

    # map property
    prop_end = marker + source[marker:].find("]")
    if decode_property(source[marker + 1:prop_end]) != "map":
        return None
    call_start = prop_end + 1
    if not source.startswith("(function(", call_start):
        return None
    params_start = call_start + len("(function")
    params_end = matching(source, params_start, "(", ")")
    params = [p.strip() for p in source[params_start + 1:params_end].split(",") if p.strip()]
    if not 1 <= len(params) <= 2 or not all(re.fullmatch(r"[A-Za-z_$][\w$]*", p) for p in params):
        return None
    body_start = params_end + 1
    if source[body_start] != "{":
        return None
    body_end = matching(source, body_start, "{", "}")
    body = source[body_start + 1:body_end].strip()
    if not body.startswith("return String["):
        return None
    string_prop_start = body.index("[")
    string_prop_end = matching(body, string_prop_start, "[", "]")
    if decode_property(body[string_prop_start + 1:string_prop_end]) != "fromCharCode":
        return None
    arg_start = string_prop_end + 1
    if body[arg_start] != "(":
        return None
    arg_end = matching(body, arg_start, "(", ")")
    if body[arg_end + 1:].strip() not in ("", ";"):
        return None
    formula = body[arg_start + 1:arg_end]

    after_body = body_end + 1
    if source[after_body] != ")":
        return None
    join_prop_start = after_body + 1
    if source[join_prop_start] != "[":
        return None
    join_prop_end = matching(source, join_prop_start, "[", "]")
    if decode_property(source[join_prop_start + 1:join_prop_end]) != "join":
        return None
    join_call_start = join_prop_end + 1
    if source[join_call_start] != "(":
        return None
    join_call_end = matching(source, join_call_start, "(", ")")

    chars = []
    for index, value in enumerate(values):
        env = {params[0]: value}
        if len(params) == 2:
            env[params[1]] = index
        # Permit an IIFE's numeric key array through key[index % key.length].
        cooked = formula
        for name, key in arrays.items():
            pat = re.compile(rf"{re.escape(name)}\[([^\]]+)%{re.escape(name)}\[([^\]]+)\]\]")
            match = pat.search(cooked)
            if match and decode_property(match.group(2)) == "length":
                key_index = eval_int(match.group(1), env) % len(key)
                cooked = cooked[:match.start()] + str(key[key_index]) + cooked[match.end():]
        chars.append(chr(eval_int(cooked, env) & 0xFFFF))
    return array_start, join_call_end + 1, "".join(chars)


def fold_direct(source: str) -> tuple[str, int]:
    count = 0
    while True:
        changed = False
        pos = 0
        while True:
            marker = source.find("['map']", pos)
            if marker < 0:
                break
            try:
                decoded = decode_map_at(source, marker)
            except (ValueError, SyntaxError, UnsafeExpression):
                decoded = None
            if decoded:
                start, end, value = decoded
                source = source[:start] + json.dumps(value) + source[end:]
                count += 1
                changed = True
                pos = start + len(value) + 2
            else:
                pos = marker + 1
        if not changed:
            return source, count


def fold_iifes(source: str) -> tuple[str, int]:
    pattern = re.compile(r"\(function\(\)\{var ([A-Za-z_$][\w$]*)=")
    count = 0
    while True:
        changed = False
        for match in list(pattern.finditer(source)):
            name = match.group(1)
            arr_start = match.end()
            if source[arr_start] != "[":
                continue
            try:
                arr_end = matching(source, arr_start, "[", "]")
                key = parse_array(source[arr_start:arr_end + 1])
                middle = source[arr_end + 1:]
                ret = re.match(r";return ", middle)
                if not ret:
                    continue
                expr_start = arr_end + 1 + ret.end()
                marker = source.find("['map']", expr_start)
                decoded = decode_map_at(source, marker, {name: key})
                if not decoded or decoded[0] != expr_start:
                    continue
                _, expr_end, value = decoded
                if not source.startswith("})()", expr_end):
                    continue
                source = source[:match.start()] + json.dumps(value) + source[expr_end + 4:]
                count += 1
                changed = True
                break
            except (ValueError, SyntaxError, UnsafeExpression):
                continue
        if not changed:
            return source, count


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} INPUT OUTPUT", file=sys.stderr)
        return 2
    source = Path(sys.argv[1]).read_text(encoding="ascii")
    total_direct = total_iife = 0
    while True:
        source, iife = fold_iifes(source)
        source, direct = fold_direct(source)
        total_iife += iife
        total_direct += direct
        if not iife and not direct:
            break
    Path(sys.argv[2]).write_text(source, encoding="utf-8")
    print(f"folded {total_direct} direct decoders and {total_iife} keyed IIFE decoders")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
