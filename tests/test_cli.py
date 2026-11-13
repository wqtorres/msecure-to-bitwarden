import json
import os
import subprocess
import sys

import pytest

import msecure_to_bitwarden
from msecure_to_bitwarden.cli import main


@pytest.fixture
def export_copy(tmp_path, sample_export_path):
    """A copy of the sample export inside a temporary folder."""
    destination = tmp_path / "export.csv"
    destination.write_bytes(sample_export_path.read_bytes())
    return destination


def test_default_output_name_and_content(export_copy):
    assert main([str(export_copy)]) == 0
    output = export_copy.with_name("export.bitwarden.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    assert len(data["items"]) == 6
    assert data["folders"] == []


def test_custom_output_path(export_copy, tmp_path):
    output = tmp_path / "custom.json"
    assert main([str(export_copy), "-o", str(output)]) == 0
    assert output.is_file()


def test_folder_by_type_switch(export_copy, tmp_path):
    output = tmp_path / "out.json"
    assert main([str(export_copy), "-o", str(output), "--folder-by-type"]) == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert len(data["folders"]) == 5


def test_missing_input_file_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as error:
        main([str(tmp_path / "missing.csv")])
    assert error.value.code == 2


def test_output_equal_to_input_is_refused(export_copy):
    original = export_copy.read_bytes()
    with pytest.raises(SystemExit) as error:
        main([str(export_copy), "-o", str(export_copy)])
    assert error.value.code == 2
    assert export_copy.read_bytes() == original  # input untouched


def test_removed_folder_by_option_is_rejected(export_copy):
    with pytest.raises(SystemExit) as error:
        main([str(export_copy), "--folder-by", "type"])
    assert error.value.code == 2


def test_input_that_is_not_utf8_is_a_usage_error(tmp_path):
    bad_file = tmp_path / "latin1.csv"
    bad_file.write_bytes("Caf\xe9|1,Login,,\n".encode("latin-1"))
    with pytest.raises(SystemExit) as error:
        main([str(bad_file)])
    assert error.value.code == 2


@pytest.mark.skipif(os.name == "nt", reason="Unix permissions only")
def test_output_is_readable_only_by_the_owner(export_copy):
    main([str(export_copy)])
    output = export_copy.with_name("export.bitwarden.json")
    assert output.stat().st_mode & 0o777 == 0o600


def test_version_option(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--version"])
    assert error.value.code == 0
    assert msecure_to_bitwarden.__version__ in capsys.readouterr().out


def test_help_mentions_the_folder_switch(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.value.code == 0
    assert "--folder-by-type" in capsys.readouterr().out


def test_runs_as_a_module(export_copy):
    result = subprocess.run(
        [sys.executable, "-m", "msecure_to_bitwarden", str(export_copy)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert export_copy.with_name("export.bitwarden.json").is_file()
