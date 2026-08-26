import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pii_data_leak_scanner import (
    build_json_report,
    build_report,
    collect_files,
    find_credit_cards,
    find_ibans,
    iban_valid,
    luhn_valid,
    main,
    redact,
    scan_directory,
    scan_file,
    scan_line,
    scan_text,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


def types_in(findings):
    return [f["type"] for f in findings]


def test_luhn_valid_known_test_card():
    assert luhn_valid("4111111111111111") is True


def test_luhn_invalid_when_last_digit_wrong():
    assert luhn_valid("4111111111111112") is False


def test_iban_valid_known_example():
    assert iban_valid("GB82WEST12345698765432") is True
    assert iban_valid("DE89370400440532013000") is True


def test_iban_invalid_random_string():
    assert iban_valid("GB00WEST00000000000000") is False


def test_iban_invalid_wrong_length():
    assert iban_valid("GB82WEST1") is False


def test_redact_masks_middle_keeps_edges():
    value = "john.doe@example.com"
    redacted = redact(value)
    assert redacted.startswith("jo") and redacted.endswith("om")
    assert set(redacted[2:-2]) == {"*"}
    assert len(redacted) == len(value)


def test_redact_short_value_fully_masked():
    assert redact("abc") == "***"


def test_email_detected():
    hits = scan_line("Contact: jane.doe@example-support.com for details.")
    assert ("email", "jane.doe@example-support.com") in hits


def test_ssn_detected():
    hits = scan_line("SSN on file: 123-45-6789.")
    assert ("ssn_us", "123-45-6789") in hits


def test_ssn_with_invalid_area_number_not_detected():
    hits = scan_line("Reference code: 000-12-3456 and 666-12-3456 and 987-65-4321")
    assert not any(t == "ssn_us" for t, _ in hits)


def test_credit_card_luhn_valid_detected():
    hits = find_credit_cards("Card on file: 4111 1111 1111 1111.")
    assert hits == ["4111 1111 1111 1111"]


def test_credit_card_luhn_invalid_not_detected():
    hits = find_credit_cards("Random 16-digit number: 1234567890123456.")
    assert hits == []


def test_iban_detected_in_line():
    hits = find_ibans("Wire to GB82WEST12345698765432 please.")
    assert hits == ["GB82WEST12345698765432"]


def test_iban_embedded_in_other_iban_like_text_not_falsely_matched():
    hits = find_ibans("Reference GB00WEST00000000000000 is not a valid IBAN.")
    assert hits == []


def test_phone_number_detected():
    hits = scan_line("Call us at 555-123-4567 anytime.")
    assert ("phone_number", "555-123-4567") in hits


def test_no_pii_in_clean_line():
    assert scan_line("This is a perfectly normal sentence with no PII at all.") == []


def test_scan_text_reports_correct_line_numbers():
    text = "line one is clean\nline two has an email: a@b.com\nline three is clean too"
    findings = scan_text(text, "test.txt")
    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert findings[0]["type"] == "email"


def test_scan_text_never_includes_raw_value():
    text = "SSN: 123-45-6789"
    findings = scan_text(text, "test.txt")
    for f in findings:
        assert "123-45-6789" not in json.dumps(f)
        assert "redacted_value" in f


def test_scan_file_on_clean_notes_has_no_findings():
    assert scan_file(SAMPLES / "clean_notes.txt") == []


def test_scan_file_on_leaked_export_finds_all_categories():
    findings = scan_file(SAMPLES / "leaked_export.csv")
    found_types = set(types_in(findings))
    assert found_types == {"email", "ssn_us", "credit_card", "iban", "phone_number"}
    assert sum(1 for f in findings if f["type"] == "email") == 2
    assert sum(1 for f in findings if f["type"] == "credit_card") == 2
    assert sum(1 for f in findings if f["type"] == "iban") == 2


def test_scan_file_missing_file_returns_empty_not_raises(tmp_path):
    assert scan_file(tmp_path / "does_not_exist.txt") == []


def test_collect_files_skips_excluded_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret", encoding="utf-8")
    (tmp_path / "real.txt").write_text("hello", encoding="utf-8")
    files = collect_files(tmp_path)
    names = {f.name for f in files}
    assert "real.txt" in names
    assert "config" not in names


def test_scan_directory_aggregates_all_files(tmp_path):
    (tmp_path / "a.txt").write_text("contact a@b.com", encoding="utf-8")
    (tmp_path / "b.txt").write_text("no pii here", encoding="utf-8")
    findings = scan_directory(tmp_path)
    assert len(findings) == 1
    assert findings[0]["type"] == "email"


def test_build_report_includes_type_breakdown_and_table():
    findings = scan_file(SAMPLES / "leaked_export.csv")
    report = build_report(findings, "leaked_export.csv")
    assert "email:" in report
    assert "credit_card:" in report
    assert "HIGH" in report


def test_build_report_clean_says_no_pii_detected():
    report = build_report([], "clean_notes.txt")
    assert "No PII detected." in report


def test_json_report_is_valid_and_matches_findings():
    findings = scan_file(SAMPLES / "leaked_export.csv")
    payload = json.loads(build_json_report(findings, "leaked_export.csv"))
    assert payload["summary"]["high"] == sum(1 for f in findings if f["severity"] == "HIGH")
    assert len(payload["findings"]) == len(findings)
    assert "by_type" in payload["summary"]


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["pii_data_leak_scanner.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_leaked_export(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "leaked_export.csv", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_clean_notes(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "clean_notes.txt", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "leaked_export.csv", []) == 0
