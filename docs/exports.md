# Exports

| Format | الأمر | ملاحظات |
|---|---|---|
| JSON | `-f json -o out.json` | كامل التفاصيل |
| CSV | `-f csv -o out.csv` | جدول النتائج |
| IP list | `-f txt -o ips.txt` | IPs فقط |
| Markdown | `-f md -o out.md` | تقرير مقروء |
| **PDF** | `-f pdf -o out.pdf` | تقرير جاهز للعميل (`[pdf]` extra) |
| **SARIF** | `-f sarif -o out.sarif` | GitHub/VS Code (`--ci` بيطلعه تلقائي) |
| Nuclei | `-f nuclei -o t.yaml` | قالب nuclei |
| **التوقيع** | `--sign` | ed25519 على أي صيغة — شوف [Signing](signing.md) |

امتداد الملف له الأولوية على `-f`: `-o report.md` دايمًا Markdown.
