import re
from pathlib import PureWindowsPath


# PowerShell executables, identified by file name on disk (Image) or by the
# name compiled into the binary (Sysmon OriginalFileName). OriginalFileName
# still says "PowerShell.EXE" when an attacker copies powershell.exe to
# another name, so checking it defeats simple renaming (MITRE T1036.003).
POWERSHELL_IMAGE_NAMES = {"powershell.exe", "pwsh.exe"}
POWERSHELL_ORIGINAL_FILE_NAMES = {"powershell.exe", "pwsh.dll"}

# PowerShell accepts any unambiguous prefix of a parameter name, so
# -e, -en, -enc ... -EncodedCommand all mean the same thing. -ec is an
# explicit alias. We build the list instead of hard-coding three spellings.
FULL_PARAMETER_NAME = "encodedcommand"
ENCODED_COMMAND_NAMES = sorted(
    {FULL_PARAMETER_NAME[:length] for length in range(1, len(FULL_PARAMETER_NAME) + 1)} | {"ec"},
    key=len,
    reverse=True,
)

# Characters accepted in front of a parameter name: the ASCII hyphen, the
# slash, and Unicode dashes (en dash, em dash, horizontal bar) that are
# sometimes used to evade detections that only look for "-".
PARAMETER_PREFIX_CHARACTERS = ("-", "/", "\u2013", "\u2014", "\u2015")
PARAMETER_PREFIX = "[" + "".join(re.escape(char) for char in PARAMETER_PREFIX_CHARACTERS) + "]"

ENCODED_COMMAND_OPTION = (
    r'(?:^|\s)"?'
    + PARAMETER_PREFIX
    + "(?:" + "|".join(ENCODED_COMMAND_NAMES) + ")"
    + r'"?(?=\s|$)'
)


def is_powershell(event: dict) -> bool:
    """True when the image name or the PE original file name is PowerShell."""
    image_name = PureWindowsPath(event.get("image") or "").name.casefold()
    original_name = (event.get("original_file_name") or "").casefold()
    return (
        image_name in POWERSHELL_IMAGE_NAMES
        or original_name in POWERSHELL_ORIGINAL_FILE_NAMES
    )


def detect_powershell_signals(event: dict) -> list[str]:
    if not is_powershell(event):
        return []

    command_line = event.get("command_line") or ""
    if re.search(ENCODED_COMMAND_OPTION, command_line, re.IGNORECASE):
        return ["powershell_encoded_command"]

    return []
