import re
from pathlib import PureWindowsPath


ENCODED_COMMAND_OPTION = (
    r'(?:^|\s)(?:-(?:EncodedCommand|ec|e)|"-(?:EncodedCommand|ec|e)")(?=\s|$)'
)


def detect_powershell_signals(event: dict) -> list[str]:
    executable = PureWindowsPath(event.get("image") or "").name.casefold()
    if executable not in {"powershell.exe", "pwsh.exe"}:
        return []

    command_line = event.get("command_line") or ""
    if re.search(ENCODED_COMMAND_OPTION, command_line, re.IGNORECASE):
        return ["powershell_encoded_command"]

    return []