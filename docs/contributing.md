# Contributing

1. Fork + branch من `main`
2. `pip install -e ".[dev,all]"`
3. اكتب اختبارات لأي مصدر جديد (unit على الأقل)
4. `ruff check . && pytest -q` لازم يعدّوا
5. PR مع وصف واضح — والـ CI (Python 3.11–3.13) لازم يعدّي

شوف [Plugin Sources](plugins.md) لو مساهمتك مصدر بيانات.
