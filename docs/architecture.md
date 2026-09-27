# Architecture

```
cloudkill/
├── cli.py          Typer CLI — scan · sign · verify · profiles · sources
├── config.py       Profiles & settings
├── core/
│   ├── engine.py   Async HTTP engine (IPv6 · proxy · stealth)
│   ├── runner.py   Source orchestration + shared rate limiting
│   ├── models.py   ScanReport · EnrichedResult
│   ├── enrichment.py  6-stage pipeline
│   └── validator.py   Input validation
├── sources/        15+ data sources + entry-point plugin loader
├── enrichers/      ASN · InternetDB · scoring · JS recon · SSL
├── exporters/      JSON · CSV · MD · PDF · SARIF · Nuclei
├── cache/          SQLite result cache
├── signing.py      ed25519 report signing
└── utils/          DNS · rate limit · stealth · user agents
```

## مبدأ التصميم

1. **المصادر plugins** — داخليًا بالتسجيل، خارجيًا بـ entry points.
2. **الإثراء منفصل عن الاكتشاف** — كل مرحلة بتضيف confidence.
3. **الـ scoring محلي 100%** — بدون خدمات خارجية.
4. **الأسرار ما تسيبش الجهاز** — .gitignore + .vercelignore + ماسح أسرار قبل النشر.
