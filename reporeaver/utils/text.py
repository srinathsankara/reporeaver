"""Text utilities."""


def trunc(s: str, n: int) -> str:
    return s[:n] + "..." if len(s) > n else s


def get_context(line: str, target: str, radius: int = 40) -> str:
    idx = line.find(target)
    if idx == -1:
        return trunc(line.strip(), 150)
    start = max(0, idx - radius)
    end = min(len(line), idx + radius)
    return trunc(line[start:end].strip(), 150)


def line_of(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1
