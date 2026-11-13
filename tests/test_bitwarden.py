import json

import pytest

from msecure_to_bitwarden.bitwarden import (
    convert_to_bitwarden,
    detect_card_brand,
    parse_expiration_date,
)
from msecure_to_bitwarden.msecure import MSecureField, MSecureRecord, parse_msecure_text


@pytest.fixture
def converted(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    return convert_to_bitwarden(records)


def items_by_name(data):
    return {item["name"]: item for item in data["items"]}


@pytest.mark.parametrize(
    ("number", "brand"),
    [
        ("4111 1111 1111 1111", "Visa"),
        ("5500005555555559", "Mastercard"),
        ("2221000000000009", "Mastercard"),
        ("378282246310005", "Amex"),
        ("6011111111111117", "Discover"),
        ("30569309025904", "Diners Club"),
        ("3530111333300000", "JCB"),
        ("6200000000000005", "UnionPay"),
        ("9999999999999999", None),
        ("", None),
    ],
)
def test_card_brand_detection(number, brand):
    assert detect_card_brand(number) == brand


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("12/2028", ("12", "2028")),
        ("1/28", ("1", "2028")),
        ("2028-03", ("3", "2028")),
        ("2028-03-01", ("3", "2028")),
        ("not a date", None),
    ],
)
def test_expiration_date_parsing(value, expected):
    assert parse_expiration_date(value) == expected


def test_item_types(converted):
    items = items_by_name(converted)
    assert items["Example Mail"]["type"] == 1  # login
    assert items["Shop, Inc."]["type"] == 1
    assert items["Test Visa"]["type"] == 3  # card
    assert items["Memo"]["type"] == 2  # secure note
    assert items["Router"]["type"] == 1  # router settings with credentials -> login
    assert items["Passport"]["type"] == 2  # no credentials -> secure note


def test_only_the_matching_type_object_is_written(converted):
    """No null identity/login/card/secureNote keys (KeePassXC would add
    identity_name and identity_address attributes for a bare 'identity' key)."""
    expected_key = {1: "login", 2: "secureNote", 3: "card"}
    all_type_keys = {"login", "secureNote", "card", "identity"}
    for item in converted["items"]:
        present = all_type_keys & item.keys()
        assert present == {expected_key[item["type"]]}
    assert '"identity"' not in json.dumps(converted)


def test_login_data(converted):
    login = items_by_name(converted)["Example Mail"]["login"]
    assert login["username"] == "alice@example.com"
    assert login["password"] == "pa|ss"
    assert login["uris"] == [{"match": None, "uri": "https://mail.example.com"}]


def test_one_time_password_becomes_totp(converted):
    login = items_by_name(converted)["Shop, Inc."]["login"]
    assert login["totp"] == "JBSWY3DPEHPK3PXP"


def test_card_data(converted):
    card = items_by_name(converted)["Test Visa"]["card"]
    assert card == {
        "cardholderName": "Alice Example",
        "brand": "Visa",
        "number": "4111111111111111",
        "expMonth": "12",
        "expYear": "2028",
        "code": "123",
    }


def test_converted_original_type_is_kept_in_a_field(converted):
    router_fields = {f["name"]: f["value"] for f in items_by_name(converted)["Router"]["fields"]}
    assert router_fields["mSecure type"] == "Router Settings"
    mail_fields = {f["name"] for f in items_by_name(converted)["Example Mail"]["fields"]}
    assert "mSecure type" not in mail_fields  # plain logins need no marker


def test_tags_are_stored_in_a_custom_field(converted):
    fields = {f["name"]: f["value"] for f in items_by_name(converted)["Test Visa"]["fields"]}
    assert fields["Tags"] == "Finance, Primary"
    shop_fields = {f["name"] for f in items_by_name(converted)["Shop, Inc."]["fields"]}
    assert "Tags" not in shop_fields


def test_secret_fields_are_hidden_and_others_are_text():
    record = MSecureRecord(
        title="X", record_type="Bank Account", tags=[], notes="",
        fields=[
            MSecureField("PIN", 9, "1234"),
            MSecureField("Account", 3, "AB-1"),
        ],
    )
    item = convert_to_bitwarden([record])["items"][0]
    types = {field["name"]: field["type"] for field in item["fields"]}
    assert types["PIN"] == 1  # hidden
    assert types["Account"] == 0  # text


def test_no_folders_by_default(converted):
    assert converted["folders"] == []
    assert all(item["folderId"] is None for item in converted["items"])


def test_folder_by_type(sample_export_text):
    records, _ = parse_msecure_text(sample_export_text)
    data = convert_to_bitwarden(records, folder_by_type=True)
    folder_names = {folder["id"]: folder["name"] for folder in data["folders"]}
    assert sorted(folder_names.values()) == sorted(
        ["Login", "Credit Card", "Secure Note", "Router Settings", "Passport"]
    )
    items = items_by_name(data)
    assert folder_names[items["Example Mail"]["folderId"]] == "Login"
    assert folder_names[items["Shop, Inc."]["folderId"]] == "Login"
    assert folder_names[items["Test Visa"]["folderId"]] == "Credit Card"


def test_line_breaks_are_valid_json_escapes(converted):
    text = json.dumps(converted)
    assert "\\n" in text  # JSON escape for a line break
    assert "\\\\n" not in text  # never a double-escaped literal backslash-n
    reloaded = json.loads(text)
    assert items_by_name(reloaded)["Memo"]["notes"] == "line one\nline two"


def test_output_is_marked_unencrypted(converted):
    assert converted["encrypted"] is False
