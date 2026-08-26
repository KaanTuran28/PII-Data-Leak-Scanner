# PII Data Leak Scanner

![CI](https://github.com/KaanTuran28/PII-Data-Leak-Scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

Scans a file or directory for accidentally leaked PII — a DLP/compliance-style check for a data export, log dump, or repo *before* it's shared externally (with a vendor, a bug tracker, or a git remote). Every matched value is redacted before it's ever written to a report; the raw value never leaves memory.

> Companion projects: [`LLM-Output-Guardrail`](../LLM-Output-Guardrail) scans **LLM output** specifically (with a `wrap()` helper for guardrailing a live call); [`Git-Secrets-Scanner`](../Git-Secrets-Scanner) looks for **credentials/API keys** in a codebase. This tool is for PII in arbitrary files/exports — a different data class and a different use case from both.

### Overview

- **Email addresses**
- **US Social Security Numbers** — with SSA-format validation (rejects `000`/`666`/`9xx` area numbers, `00` group, `0000` serial), so it doesn't flag every `\d{3}-\d{2}-\d{4}`-shaped string.
- **Credit card numbers** — candidate 13–19 digit runs are **Luhn-checksum validated**, so an arbitrary 16-digit number isn't flagged as a card.
- **IBANs** — candidates are **mod-97 checksum validated** per the ISO 7064 algorithm, so random `[A-Z]{2}\d{2}[A-Z0-9]+`-shaped text isn't flagged.
- **Phone numbers** (US-style)

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd PII-Data-Leak-Scanner
pip install -e .
```

This installs a `pii-data-leak-scanner` command. You can also run the script directly with `python pii_data_leak_scanner.py` without installing.

### Usage

```bash
pii-data-leak-scanner --path export.csv --output report.md
pii-data-leak-scanner --path ./data-dump/ --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single file, or a directory to scan recursively |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

Directory scans skip `.git`, `__pycache__`, `.venv`/`venv`, `node_modules`, and lint/test cache folders. Files that can't be decoded as UTF-8 (binaries) are skipped, not errored on.

### CI Integration

Run this against an export or archive before it leaves your infrastructure:

```bash
pii-data-leak-scanner --path ./export/ --fail-on high
```

```yaml
# GitHub Actions step (e.g. before publishing a data artifact)
- name: Scan export for leaked PII
  run: pii-data-leak-scanner --path ./export/ --fail-on high
```

### Example Output

[`sample_data/leaked_export.csv`](./sample_data/leaked_export.csv) contains two synthetic rows with an email, SSN, Luhn-valid test credit card number, valid-checksum IBAN, and phone number each (all fictional/test values — the credit card numbers are the well-known Visa/Mastercard test numbers, and the IBANs are the published ISO example IBANs). [`sample_data/clean_notes.txt`](./sample_data/clean_notes.txt) has none. See [`sample_report.md`](./sample_report.md) — real output from scanning `leaked_export.csv`: 10 findings (6 HIGH, 2 MEDIUM, 2 LOW), every value redacted.

### Limitations

Regex + checksum heuristics, not a full Presidio-style NLP PII detector — it won't catch names, addresses, or PII in languages/formats outside these patterns, and phone-number matching is US-format-biased. Treat it as a fast pre-flight check, not a certification that a file contains no PII.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
PII-Data-Leak-Scanner/
├── pii_data_leak_scanner.py
├── pyproject.toml
├── sample_data/
│   ├── leaked_export.csv
│   └── clean_notes.txt
├── sample_report.md
├── tests/
│   └── test_pii_data_leak_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Bir dosyayı veya dizini yanlışlıkla sızdırılmış PII (kişisel olarak tanımlanabilir bilgi) için tarar — bir veri dışa aktarımının, log dökümünün veya reponun *dışarıya paylaşılmadan önce* (bir tedarikçiyle, bir hata izleyiciyle veya bir git remote'uyla) kontrolü için DLP/uyumluluk (compliance) tarzı bir denetim. Eşleşen her değer, bir rapora yazılmadan önce maskelenir; ham değer asla bellekten çıkmaz.

> Tamamlayıcı projeler: [`LLM-Output-Guardrail`](../LLM-Output-Guardrail) özellikle **LLM çıktısını** tarar (canlı bir çağrıyı korumak için bir `wrap()` yardımcı fonksiyonuyla); [`Git-Secrets-Scanner`](../Git-Secrets-Scanner) bir kod tabanında **kimlik bilgileri/API anahtarları** arar. Bu araç ise keyfi dosyalardaki/dışa aktarımlardaki PII içindir — her ikisinden de farklı bir veri sınıfı ve farklı bir kullanım senaryosu.

### Genel Bakış

- **E-posta adresleri**
- **ABD Sosyal Güvenlik Numaraları (SSN)** — SSA format doğrulamasıyla birlikte (`000`/`666`/`9xx` alan numaralarını, `00` grubunu, `0000` seri numarasını reddeder), böylece `\d{3}-\d{2}-\d{4}` biçimindeki her dizgiyi işaretlemez.
- **Kredi kartı numaraları** — aday 13-19 haneli diziler **Luhn sağlama toplamı (checksum)** ile doğrulanır, böylece rastgele 16 haneli bir sayı kart olarak işaretlenmez.
- **IBAN'lar** — adaylar ISO 7064 algoritmasına göre **mod-97 sağlama toplamı** ile doğrulanır, böylece rastgele `[A-Z]{2}\d{2}[A-Z0-9]+` biçimindeki metin işaretlenmez.
- **Telefon numaraları** (ABD tarzı)

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd PII-Data-Leak-Scanner
pip install -e .
```

Bu, bir `pii-data-leak-scanner` komutu kurar. Kurulum yapmadan da doğrudan `python pii_data_leak_scanner.py` ile betiği çalıştırabilirsiniz.

### Kullanım

```bash
pii-data-leak-scanner --path export.csv --output report.md
pii-data-leak-scanner --path ./data-dump/ --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir dosya veya özyinelemeli olarak taranacak bir dizin |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde veya üzerinde bir bulgu varsa çıkış kodu `1` |

Dizin taramaları `.git`, `__pycache__`, `.venv`/`venv`, `node_modules` ve lint/test önbellek klasörlerini atlar. UTF-8 olarak çözümlenemeyen dosyalar (ikili dosyalar) hata vermeden atlanır.

### CI Entegrasyonu

Bunu, bir dışa aktarım veya arşiv altyapınızdan ayrılmadan önce çalıştırın:

```bash
pii-data-leak-scanner --path ./export/ --fail-on high
```

```yaml
# GitHub Actions adımı (örn. bir veri artifact'ı yayımlanmadan önce)
- name: Scan export for leaked PII
  run: pii-data-leak-scanner --path ./export/ --fail-on high
```

### Örnek Çıktı

[`sample_data/leaked_export.csv`](./sample_data/leaked_export.csv), her biri bir e-posta, SSN, Luhn açısından geçerli test kredi kartı numarası, geçerli sağlama toplamlı IBAN ve telefon numarası içeren iki sentetik satır barındırır (tüm değerler kurgusal/test değerleridir — kredi kartı numaraları bilinen Visa/Mastercard test numaraları, IBAN'lar ise yayımlanmış ISO örnek IBAN'larıdır). [`sample_data/clean_notes.txt`](./sample_data/clean_notes.txt) dosyasında hiçbiri yoktur. `leaked_export.csv` taramasından gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 10 bulgu (6 HIGH, 2 MEDIUM, 2 LOW), her değer maskelenmiş.

### Sınırlamalar

Regex + sağlama toplamı sezgiselleridir, tam bir Presidio tarzı NLP tabanlı PII dedektörü değildir — isimleri, adresleri veya bu kalıpların dışındaki dillerde/formatlardaki PII'yi yakalamaz ve telefon numarası eşleştirmesi ABD formatına yatkındır. Bunu, bir dosyanın PII içermediğine dair bir sertifikasyon olarak değil, hızlı bir ön kontrol olarak değerlendirin.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
PII-Data-Leak-Scanner/
├── pii_data_leak_scanner.py
├── pyproject.toml
├── sample_data/
│   ├── leaked_export.csv
│   └── clean_notes.txt
├── sample_report.md
├── tests/
│   └── test_pii_data_leak_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
