from msecure_to_bitwarden.msecure import parse_msecure_text, read_msecure_file


def records_by_title(records):
    return {record.title: record for record in records}


def test_all_records_are_read(sample_export_text):
    records, unparsable = parse_msecure_text(sample_export_text)
    assert unparsable == []
    assert [record.title for record in records] == [
        "Example Mail", "Shop, Inc.", "Test Visa", "Memo", "Router", "Passport",
    ]


def test_banner_line_is_discarded(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    assert not any("mSecure6" in record.title for record in records)


def test_file_without_banner_keeps_first_record():
    records, _ = parse_msecure_text("Solo|1,Secure Note,,hello\n")
    assert [record.title for record in records] == ["Solo"]


def test_empty_text_gives_no_records():
    assert parse_msecure_text("") == ([], [])


def test_multiline_notes_become_real_line_breaks(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    notes = records_by_title(records)["Example Mail"].notes
    assert notes == "Recovery codes:\n1111-2222\n\n3333-4444"


def test_no_literal_backslash_n_marker_is_left(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    for record in records:
        assert "\\n" not in record.notes
        assert all("\\n" not in field.value for field in record.fields)


def test_trailing_empty_continuation_line_is_trimmed(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    assert records_by_title(records)["Memo"].notes == "line one\nline two"


def test_line_breaks_inside_a_field_value(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    router = records_by_title(records)["Router"]
    admin_note = next(field for field in router.fields if field.name == "Admin note")
    assert admin_note.value == "first line\nsecond line"


def test_quoted_title_containing_a_comma(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    assert "Shop, Inc." in records_by_title(records)


def test_tags_are_split(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    assert records_by_title(records)["Test Visa"].tags == ["Finance", "Primary"]
    assert records_by_title(records)["Shop, Inc."].tags == []


def test_pipe_inside_a_password_is_preserved(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    mail = records_by_title(records)["Example Mail"]
    password = next(field for field in mail.fields if field.field_type == 8)
    assert password.value == "pa|ss"


def test_fields_without_value_are_discarded(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    all_names = {field.name for record in records for field in record.fields}
    assert {"Phone", "Empty", "PIN", "Country"}.isdisjoint(all_names)
    assert all(field.value.strip() for record in records for field in record.fields)


def test_windows_line_endings_give_identical_result(sample_export_text):
    unix_records, _ = parse_msecure_text(sample_export_text)
    windows_records, _ = parse_msecure_text(sample_export_text.replace("\n", "\r\n"))
    assert windows_records == unix_records


def test_byte_order_mark_is_accepted(tmp_path, sample_export_text):
    path = tmp_path / "bom.csv"
    path.write_bytes(b"\xef\xbb\xbf" + sample_export_text.encode("utf-8"))
    records, unparsable = read_msecure_file(path)
    assert unparsable == []
    assert len(records) == 6
