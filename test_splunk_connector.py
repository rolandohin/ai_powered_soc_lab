"""Offline tests: the Splunk pre-filter must agree with the Python rule."""

import re

import pytest

from splunk_connector import SPL, build_detection_spl
from test_detection_rules import FALSE_POSITIVE_TRAPS, TRUE_POSITIVES


def spl_command_line_regex(spl: str) -> re.Pattern[str]:
    """Extract the CommandLine regex from the SPL and undo SPL quote escaping."""
    match = re.search(r'match\(CommandLine, "(.*)"\)', spl)
    assert match, "CommandLine filter not found in SPL"
    return re.compile(match.group(1).replace('\\"', '"'))


def test_spl_is_bounded_and_returns_original_file_name():
    spl = build_detection_spl(5)
    assert "| head 5" in spl
    assert "OriginalFileName" in spl.splitlines()[-1]
    assert 'in(lower(OriginalFileName), "powershell.exe", "pwsh.dll")' in spl
    assert "encoded_switch" not in spl


@pytest.mark.parametrize("command_line", TRUE_POSITIVES.values(), ids=TRUE_POSITIVES.keys())
def test_spl_prefilter_keeps_every_true_positive(command_line):
    assert spl_command_line_regex(SPL).search(command_line)


@pytest.mark.parametrize("command_line", FALSE_POSITIVE_TRAPS.values(), ids=FALSE_POSITIVE_TRAPS.keys())
def test_spl_prefilter_drops_false_positive_traps(command_line):
    assert not spl_command_line_regex(SPL).search(command_line)
