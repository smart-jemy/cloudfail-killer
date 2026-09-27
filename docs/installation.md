# Installation

```bash
pip install "cloudkill[all]"      # كل شيء: تصدير + PDF + توقيع
```

أو على حدة حسب الحاجة:

```bash
pip install cloudkill             # الأساس
pip install "cloudkill[pdf]"      # + تقارير PDF
pip install "cloudkill[export]"   # + WeasyPrint exports
pip install "cloudkill[sign]"     # + ed25519 report signing
pip install "cloudkill[dev]"      # + pytest · ruff · mypy · bandit
```

يتطلب Python 3.11+.

## من Docker

```bash
docker build -t cloudkill -f docker/Dockerfile .
docker run --rm cloudkill scan example.com --profile researcher
```

## من المصدر

```bash
git clone https://github.com/smart-jemy/cloudfail-killer.git
cd cloudfail-killer
pip install -e ".[dev]"
pytest -q                          # 374 اختبار
```
