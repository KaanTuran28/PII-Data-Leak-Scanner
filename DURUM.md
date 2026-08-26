# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Dosya/dizin taraması yapıp PII sızıntısı tespit eden DLP-tarzı CLI aracı — e-posta, ABD SSN (SSA format doğrulamasıyla — 000/666/9xx alan kodu, 00 grup, 0000 seri hariç tutuluyor), kredi kartı (Luhn checksum doğrulamalı), IBAN (mod-97 checksum doğrulamalı, ISO 7064), telefon numarası. `LLM-Output-Guardrail` (LLM çıktısına özel) ve `Git-Secrets-Scanner` (credential'lara özel) ile bilinçli olarak farklı bir veri sınıfını hedefliyor — README'de çapraz referans var.
- Checksum doğrulaması sayesinde yanlış pozitif üretmiyor: rastgele 16 haneli bir sayı ya da rastgele `[A-Z]{2}\d{2}...` biçimli bir metin "kredi kartı"/"IBAN" diye işaretlenmiyor — sadece gerçekten checksum'ı tutan değerler.
- Test sırasında küçük bir hata yakalandı: `redact()` çıktısının tam yıldız sayısını elle tahmin edip test'e yazmıştım, 1 karakter farkla yanlıştı — gerçek çalıştırmayla düzeltildi, test artık sabit string yerine uzunluk/karakter-seti kontrolü yapıyor (daha sağlam, gelecekte tekrar elle sayım hatası riski yok).
- Dosya: `pii_data_leak_scanner.py`, 2 örnek dosya (`leaked_export.csv` — gerçek Luhn-geçerli test kartları + gerçek ISO örnek IBAN'ları kullanıyor, `clean_notes.txt` — 0 bulgu), `tests/test_pii_data_leak_scanner.py` (29 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 29/29 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI gerçek dosyaya karşı çalıştırıldı: `leaked_export.csv` → 10 bulgu (6 HIGH, 2 MEDIUM, 2 LOW), tüm değerler raporda redakte edilmiş halde. `sample_report.md` bu gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `PII-Data-Leak-Scanner` adıyla repo aç, git init + push.
