"""Postal addresses passed back unchanged keep Apple's own lines (X-ABADR country code, pref), and no value can smuggle in a
vCard property through a line break that str.splitlines() honours."""
from __future__ import annotations

from icloud_mcp.contacts import _replace_vcard_fields, parse_vcard

UID = "6222c2fe-845b-42e1-ad6f-97f5ef4a5643"
EMMA = "\r\n".join([
    "BEGIN:VCARD", "VERSION:3.0", "PRODID:-//Apple Inc.//iOS 27.0//EN",
    "N:Bush;Emma Jayne;;;", "FN:Emma Jayne Bush",
    "item1.ADR;type=HOME;type=pref:;;12 High Street;Hull;East Riding of Yorkshire;HU1 1AA;United Kingdom",
    "item1.X-ABADR:gb",
    "item2.ADR;type=WORK:;Haus B;Bahnhofstraße 5;München;;80335;Deutschland", "item2.X-ABADR:de",
    "ADR:;;9 Eastwold;North Newbald;England;YO43 4;Vereinigtes Königreich",
    "item3.X-ABRELATEDNAMES:Tom Bush", "item3.X-ABLabel:_$!<Brother>!$_",
    "X-SOCIALPROFILE;type=twitter:x-apple:emmajb", "NOTE:private note",
    f"UID:{UID}", "END:VCARD", ""])
STORED = EMMA.split("\r\n")[5:10]


def _back(card: str) -> list[dict]:
    return [{k: v for k, v in a.items() if k != "address"} for a in parse_vcard(card)["addresses"]]


def test_adding_an_address_keeps_the_stored_ones_byte_for_byte():
    raw = _replace_vcard_fields(EMMA, addresses=_back(EMMA) + [{"street": "27 Castle Road", "city": "Cottingham", "country": "UK"}])
    lines = raw.split("\r\n")
    assert all(line in lines for line in STORED)
    assert "ADR;TYPE=HOME:;;27 Castle Road;Cottingham;;;UK" in lines           # no postal code invented
    assert [a["street"] for a in parse_vcard(raw)["addresses"]] == ["12 High Street", "Bahnhofstraße 5", "9 Eastwold", "27 Castle Road"]


def test_unlabelled_address_matches_the_home_default():
    back = _back(EMMA)
    back[2]["label"] = "home"                                                  # what a client sending the schema default passes
    assert "ADR:;;9 Eastwold;North Newbald;England;YO43 4;Vereinigtes Königreich" in _replace_vcard_fields(EMMA, addresses=back)


def test_an_edited_address_is_regenerated_the_others_kept():
    back = _back(EMMA)
    back[1]["street"] = "Bahnhofstraße 7"
    lines = _replace_vcard_fields(EMMA, addresses=back).split("\r\n")
    assert "item1.X-ABADR:gb" in lines and "item2.X-ABADR:de" not in lines
    assert any("Bahnhofstraße 7" in line for line in lines)


def test_other_apple_fields_survive_and_empty_list_clears():
    raw = _replace_vcard_fields(EMMA, addresses=[])
    assert parse_vcard(raw)["addresses"] == [] and "X-ABADR" not in raw
    for line in ("item3.X-ABRELATEDNAMES:Tom Bush", "item3.X-ABLabel:_$!<Brother>!$_", "NOTE:private note"):
        assert line in raw.split("\r\n")


def test_unicode_line_breaks_cannot_inject_properties():
    evil = {"street": "x EMAIL:evil@attacker.test", "city": "y\x85TEL:666", "country": "z NOTE:x"}
    c = parse_vcard(_replace_vcard_fields(EMMA, addresses=[evil]))
    assert c["emails"] == [] and c["phones"] == [] and c["uid"] == UID
    assert c["addresses"][0]["street"] == "xEMAIL:evil@attacker.test"
