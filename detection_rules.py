import re
from pathlib import PureWindowsPath


def detect_powershell_signals(event: dict) -> list[str]:
    executable = PureWindowsPath(event.get("image") or "").name.casefold()
    if executable not in {"powershell.exe", "pwsh.exe"}:
        return []

    command_line = event.get("command_line") or ""
    encoded_command = re.search(
        r'(?:^|\s)(?:-EncodedCommand|"-EncodedCommand")(?=\s|$)',
        command_line,
        re.IGNORECASE,
    )

    if encoded_command:
        return ["powershell_encoded_command"]
    return []