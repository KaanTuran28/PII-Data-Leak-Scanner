# PII Data Leak Scan Report

- **Source:** sample_data/leaked_export.csv
- **Total findings:** 10 (6 HIGH, 2 MEDIUM, 2 LOW)
  - credit_card: 2
  - email: 2
  - iban: 2
  - phone_number: 2
  - ssn_us: 2

| Severity | Type | File | Line | Redacted Value |
|---|---|---|---|---|
| HIGH | ssn_us | sample_data\leaked_export.csv | 2 | `12*******89` |
| HIGH | credit_card | sample_data\leaked_export.csv | 2 | `41************11` |
| HIGH | iban | sample_data\leaked_export.csv | 2 | `GB******************32` |
| HIGH | ssn_us | sample_data\leaked_export.csv | 3 | `23*******90` |
| HIGH | credit_card | sample_data\leaked_export.csv | 3 | `55************59` |
| HIGH | iban | sample_data\leaked_export.csv | 3 | `DE******************00` |
| MEDIUM | email | sample_data\leaked_export.csv | 2 | `jo*********************om` |
| MEDIUM | email | sample_data\leaked_export.csv | 3 | `ja***********************om` |
| LOW | phone_number | sample_data\leaked_export.csv | 2 | `55********67` |
| LOW | phone_number | sample_data\leaked_export.csv | 3 | `55********43` |
