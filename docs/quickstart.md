# Quick Start

```bash
# 1. مسح سريع سلبي
cloudkill scan example.com --profile researcher

# 2. عمق bug-bounty مع إثراء كامل
cloudkill scan target.com --profile bugbounty --format pdf --sign

# 3. جاهز لخط الإنتاج
cloudkill scan target.com --ci -o findings.sarif

# 4. دفعة دومينات بالتوازي
cloudkill scan --domains targets.txt --batch-concurrency 4 --profile automation
```

## اقرأ النتائج

كل نتيجة بتطلع بـ **confidence score (0–100)** مبني على 6 مراحل إثراء:
SSL match · ASN/hosting · InternetDB verification · Favicon hash ·
JS recon · Host-header probe. أعلى من 80 = مرشح origin قوي جدًا.
