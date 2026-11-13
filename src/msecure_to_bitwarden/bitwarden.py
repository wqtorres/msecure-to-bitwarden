"""Conversion of parsed mSecure records into the Bitwarden JSON structure."""

from __future__ import annotations

import re
import uuid

from .msecure import (
    MSECURE_FIELD_CREDIT_CARD_NUMBER,
    MSECURE_FIELD_MONTH_YEAR,
    MSECURE_FIELD_ONE_TIME_PASSWORD,
    MSECURE_FIELD_PASSWORD,
    MSECURE_FIELD_TYPES_TO_HIDE,
    MSECURE_FIELD_URL,
    MSECURE_FIELD_USERNAME,
    MSecureField,
    MSecureRecord,
)

# Bitwarden item type codes
BITWARDEN_TYPE_LOGIN = 1
BITWARDEN_TYPE_SECURE_NOTE = 2
BITWARDEN_TYPE_CARD = 3

# Bitwarden custom field type codes
BITWARDEN_CUSTOM_FIELD_TEXT = 0
BITWARDEN_CUSTOM_FIELD_HIDDEN = 1


# ============================================================================
# Helpers to build Bitwarden data
# ============================================================================

def detect_card_brand(card_number: str) -> str | None:
    """Guess the card brand from the leading digits (None if unknown)."""
    digits_only = re.sub(r"\D", "", card_number)
    if not digits_only:
        return None

    first_two = int(digits_only[:2])
    first_three = int(digits_only[:3])
    first_four = int(digits_only[:4]) if len(digits_only) >= 4 else 0

    if digits_only[0] == "4":
        return "Visa"
    if 51 <= first_two <= 55 or 2221 <= first_four <= 2720:
        return "Mastercard"
    if first_two in (34, 37):
        return "Amex"
    if digits_only.startswith("6011") or first_two == 65 or 644 <= first_three <= 649:
        return "Discover"
    if 300 <= first_three <= 305 or first_two in (36, 38, 39):
        return "Diners Club"
    if 3528 <= first_four <= 3589:
        return "JCB"
    if first_two == 62:
        return "UnionPay"
    return None


def parse_expiration_date(value: str) -> tuple[str, str] | None:
    """Parse an expiration date into (month, four-digit year), or None."""
    cleaned_value = value.strip()

    # Format YYYY-MM or YYYY-MM-DD (also with slashes)
    year_first_match = re.match(r"^(\d{4})[-/](\d{1,2})(?:[-/]\d{1,2})?$", cleaned_value)
    if year_first_match:
        return str(int(year_first_match.group(2))), year_first_match.group(1)

    # Format MM/YY or MM/YYYY (also with dashes)
    month_first_match = re.match(r"^(\d{1,2})[-/](\d{2}|\d{4})$", cleaned_value)
    if month_first_match:
        year = month_first_match.group(2)
        if len(year) == 2:
            year = "20" + year  # expand a two-digit year
        return str(int(month_first_match.group(1))), year

    return None  # unknown format


def make_custom_field(field: MSecureField) -> dict:
    """Convert an mSecure field into a Bitwarden custom field.

    Secrets (passwords, sensitive numbers, card numbers, OTPs) are stored as
    hidden fields; everything else as plain text.
    """
    is_secret = field.field_type in MSECURE_FIELD_TYPES_TO_HIDE
    return {
        "name": field.name,
        "value": field.value,
        "type": BITWARDEN_CUSTOM_FIELD_HIDDEN if is_secret else BITWARDEN_CUSTOM_FIELD_TEXT,
        "linkedId": None,
    }


def make_text_custom_field(name: str, value: str) -> dict:
    """Build a plain-text Bitwarden custom field from a name and a value."""
    return {
        "name": name,
        "value": value,
        "type": BITWARDEN_CUSTOM_FIELD_TEXT,
        "linkedId": None,
    }


def build_login_data(fields: list[MSecureField]) -> tuple[dict, list[MSecureField]]:
    """Extract username/password/TOTP/URLs for a Bitwarden login.

    Returns (login dict, fields that were not used and must become custom fields).
    """
    username = None
    password = None
    totp_secret = None
    uris: list[dict] = []
    unused_fields: list[MSecureField] = []

    for field in fields:
        if field.field_type == MSECURE_FIELD_USERNAME and username is None:
            username = field.value
        elif field.field_type == MSECURE_FIELD_PASSWORD and password is None:
            password = field.value
        elif field.field_type == MSECURE_FIELD_ONE_TIME_PASSWORD and totp_secret is None:
            totp_secret = field.value
        elif field.field_type == MSECURE_FIELD_URL and field.value.strip():
            uris.append({"match": None, "uri": field.value.strip()})
        else:
            # Second username, extra password, phone number, etc.
            unused_fields.append(field)

    login = {
        "uris": uris,
        "username": username,
        "password": password,
        "totp": totp_secret,
    }
    return login, unused_fields


def build_card_data(fields: list[MSecureField]) -> tuple[dict, list[MSecureField]]:
    """Extract card number/holder/expiry/code for a Bitwarden card.

    Returns (card dict, fields that were not used and must become custom fields).
    """
    card = {
        "cardholderName": None,
        "brand": None,
        "number": None,
        "expMonth": None,
        "expYear": None,
        "code": None,
    }
    unused_fields: list[MSecureField] = []

    for field in fields:
        lowercase_name = field.name.lower()

        # Card number: the first "Credit Card Number" field.
        if field.field_type == MSECURE_FIELD_CREDIT_CARD_NUMBER and card["number"] is None:
            card["number"] = field.value
            continue

        # Expiration date: a Month/Year field, or any field named like "Expires".
        is_expiration_candidate = (
            field.field_type == MSECURE_FIELD_MONTH_YEAR or "expir" in lowercase_name
        )
        if is_expiration_candidate and card["expMonth"] is None:
            expiration = parse_expiration_date(field.value)
            if expiration:
                card["expMonth"], card["expYear"] = expiration
                continue

        # Cardholder name: matched by field name.
        if card["cardholderName"] is None and (
            "name" in lowercase_name or "holder" in lowercase_name
        ):
            card["cardholderName"] = field.value
            continue

        # Security code: matched by field name.
        if card["code"] is None and any(
            keyword in lowercase_name
            for keyword in ("security", "cvv", "cvc", "verification")
        ):
            card["code"] = field.value
            continue

        unused_fields.append(field)  # PIN, bank phone number, etc.

    if card["number"]:
        card["brand"] = detect_card_brand(card["number"])
    return card, unused_fields


def make_empty_bitwarden_item(
    name: str, notes: str, folder_id: str | None, bitwarden_type: int
) -> dict:
    """Create a Bitwarden item skeleton; the caller adds the type-specific part.

    Only the object matching the item type ("login", "card" or "secureNote")
    is added later by the caller. Unused ones are intentionally NOT written
    (not even as null): some importers, e.g. KeePassXC, test for the mere
    presence of the "identity" key and then create empty identity_name and
    identity_address attributes in every entry.
    """
    return {
        "id": str(uuid.uuid4()),
        "organizationId": None,
        "folderId": folder_id,
        "type": bitwarden_type,
        "reprompt": 0,
        "name": name,
        "notes": notes or None,
        "favorite": False,
        "fields": [],
        "collectionIds": None,
    }


# ============================================================================
# Converting all records into the Bitwarden JSON structure
# ============================================================================

def convert_to_bitwarden(
    records: list[MSecureRecord], folder_by_type: bool = False
) -> dict:
    """Build the full Bitwarden export dictionary from the parsed records.

    folder_by_type=False (default): no folders are created at all.
    folder_by_type=True: one folder per mSecure record type.
    """
    folder_ids_by_name: dict[str, str] = {}  # folder name -> generated id
    bitwarden_items: list[dict] = []

    for record in records:
        # ---- Decide the folder ----------------------------------------------
        folder_id = None
        if folder_by_type:
            # Reuse the folder if it already exists, otherwise create it.
            folder_id = folder_ids_by_name.setdefault(
                record.record_type, str(uuid.uuid4())
            )

        # ---- Decide which Bitwarden item type to create --------------------
        has_login_data = any(
            field.field_type
            in (
                MSECURE_FIELD_URL,
                MSECURE_FIELD_USERNAME,
                MSECURE_FIELD_PASSWORD,
                MSECURE_FIELD_ONE_TIME_PASSWORD,
            )
            for field in record.fields
        )
        extra_custom_fields: list[dict] = []

        if record.record_type == "Credit Card":
            # mSecure credit card -> Bitwarden card
            item = make_empty_bitwarden_item(
                record.title, record.notes, folder_id, BITWARDEN_TYPE_CARD
            )
            item["card"], unused_fields = build_card_data(record.fields)

        elif record.record_type == "Login" or (
            record.record_type != "Secure Note" and has_login_data
        ):
            # mSecure login -> Bitwarden login. Other record types that carry
            # credentials (Email Account, Router Settings, ...) also become
            # logins so autofill works, with their original type preserved.
            item = make_empty_bitwarden_item(
                record.title, record.notes, folder_id, BITWARDEN_TYPE_LOGIN
            )
            item["login"], unused_fields = build_login_data(record.fields)
            if record.record_type != "Login":
                extra_custom_fields.append(
                    make_text_custom_field("mSecure type", record.record_type)
                )

        else:
            # Everything else (Secure Note, Passport, Bank Account, ...)
            # -> Bitwarden secure note, with all fields kept as custom fields.
            item = make_empty_bitwarden_item(
                record.title, record.notes, folder_id, BITWARDEN_TYPE_SECURE_NOTE
            )
            item["secureNote"] = {"type": 0}
            unused_fields = record.fields
            if record.record_type != "Secure Note":
                extra_custom_fields.append(
                    make_text_custom_field("mSecure type", record.record_type)
                )

        # ---- Attach custom fields ------------------------------------------
        item["fields"] = extra_custom_fields + [
            make_custom_field(field) for field in unused_fields
        ]
        # Bitwarden has no tags, so all mSecure tags are kept in one text field.
        if record.tags:
            item["fields"].append(
                make_text_custom_field("Tags", ", ".join(record.tags))
            )

        bitwarden_items.append(item)

    return {
        "encrypted": False,  # plaintext export
        "folders": [
            {"id": folder_id, "name": folder_name}
            for folder_name, folder_id in folder_ids_by_name.items()
        ],
        "items": bitwarden_items,
    }
