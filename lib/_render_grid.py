#!/usr/bin/env python3
"""虚拟表格渲染器 - 无边框, cell 内超长自动换行, 列对齐, 正确处理 ANSI 颜色码.

调用方式:
  printf '%s\x1f%s\x1f%s' "$c1" "$c2" "$c3" | python3 _render_grid.py col_width

输出多行, 每行三个 cell 用空格分隔, 每个 cell 按 col_width 字符宽度对齐.
ANSI 颜色码 (\\033[..m) 视为零宽不可见, 切行时保留在原位不切坏.
"""
import sys
import re
import unicodedata

SEP = "\x1f"   # Unit Separator, 不会出现在 app 名称里
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_width(s: str) -> int:
    """算可见列数: CJK / 全角 / emoji 算 2, ASCII / 半角 算 1, ANSI 码算 0."""
    s2 = ANSI_RE.sub("", s)
    w = 0
    for c in s2:
        ea = unicodedata.east_asian_width(c)
        w += 2 if ea in ("F", "W") else 1
    return w


def wrap(text: str, col_width: int) -> list[str]:
    """按 col_width 可见宽切行, ANSI 码保留在原位, 不切到一半."""
    result: list[str] = []
    line = ""
    line_w = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # ANSI 颜色码: 整段保留, 不计宽度
        if ch == "\x1b":
            m = ANSI_RE.match(text[i:])
            if m:
                line += m.group()
                i += len(m.group())
                continue
        # UTF-8 多字节字符: 取完整字符
        if ord(ch) >= 0x80:
            j = i + 1
            while j < n and 0x80 <= ord(text[j]) < 0xC0:
                j += 1
            ch = text[i:j]
            i = j
        else:
            i += 1
        cw = visible_width(ch)
        if line_w + cw > col_width and line_w > 0:
            result.append(line)
            line = ch
            line_w = cw
        else:
            line += ch
            line_w += cw
    if line:
        result.append(line)
    return result


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: _render_grid.py col_width < cells_on_stdin_sep_by_x1f")
    col_width = int(sys.argv[1])

    data = sys.stdin.read()
    cells = data.split(SEP)
    if cells and cells[-1] == "":
        cells = cells[:-1]
    if not cells:
        return

    cell_lines = [wrap(c, col_width) for c in cells]
    max_lines = max(len(lst) for lst in cell_lines)

    for row in range(max_lines):
        parts = []
        for ci, lines in enumerate(cell_lines):
            line = lines[row] if row < len(lines) else ""
            w = visible_width(line)
            pad = col_width - w
            parts.append(line + " " * max(0, pad))
            if ci < len(cell_lines) - 1:
                parts.append(" ")
        sys.stdout.write("".join(parts) + "\n")


if __name__ == "__main__":
    main()
