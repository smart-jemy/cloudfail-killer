# Live Demo

سجل حقيقي 100% من تشغيل فعلي للأداة (`--version` · `--help` · `profiles` · `sources`)
— مفيش أي تمثيل، الإطارات من stdout الأصلي.

## شغل الديمو في الترمنال

```bash
# ملف asciinema v2 قياسي — يتشغل بأي مشغل
asciinema play docs/assets/demo.cast

# أو أعد توليده من نسختك المحلية (الناتج بتاعك الحقيقي)
python scripts/make-demo.py
```

## على موقع التوثيق

صفحة الـ demo على [GitHub Pages](https://smart-jemy.github.io/cloudfail-killer/demo/)
بتعرض نفس السجل بمشغل asciinema داخل الصفحة.

## محتوى السجل

| الأمر | بيعرض إيه |
|---|---|
| `cloudkill --version` | إصدار الأداة |
| `cloudkill --help` | الأوامر: scan · sign · verify · profiles · sources |
| `cloudkill profiles` | البروفايلات الخمسة وأوصافها |
| `cloudkill sources` | 15+ مصدر وحالة المفاتيح لكل واحد |
