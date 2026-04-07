<div align="center" dir="rtl">

# 🛡️ جهاز إنذار جياقو المتقدم — الإصدار 2.0

### إطار عمل متقدم لفك حماية APK وجنائيات البرمجيات الخبيثة

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

*إطار عمل معياري ثنائي المحرك لفك ضغط تطبيقات Android المحمية بتقنية **360 Jiagu (加固)** وإجراء تحليل جنائي عميق للبرمجيات الخبيثة.*

</div>

---

<div dir="rtl">

## 🧬 لماذا 360 Jiagu؟

يُعدّ **360 Jiagu** من أكثر أدوات الحماية التجارية انتشارًا لتطبيقات Android في الصين، إذ يُستخدم في أكثر من 100,000 تطبيق. وعلى الرغم من غرضه المشروع في حماية الملكية الفكرية، إلا أن **مؤلفي البرمجيات الخبيثة يسيئون استخدامه على نطاق واسع** للتهرب من التحليل الثابت لبرامج مكافحة الفيروسات.

**المشكلة:**
- التطبيقات المحزومة تجعل التحليل الثابت التقليدي عديم الفائدة — يتم تشفير الكود الأصلي داخل مكتبات `.so` أصلية
- تستخدم الأداة آليات مضادة للتصحيح ومضادة لـ Frida وفحوصات سلامة للحيلولة دون الاستخراج أثناء التشغيل
- يحتاج الباحثون الأمنيون إلى أدوات موثوقة لاسترداد DEX الأصلي لتحليل البرمجيات الخبيثة

**نهج JiaguSentinel:**
- **المحرك الثابت**: اكتشاف الحمولة بناءً على الانتروبيا + مطابقة الأنماط البايتية + فك الضغط متعدد الطبقات لاستخراج DEX دون تشغيل التطبيق
- **المحرك الديناميكي**: إزالة حماية الذاكرة عبر Frida مع تجاوز متقدم للكشف وتصوير DEX المفكوك أثناء التشغيل
- **محرك التحليلات**: تسجيل تهديدات آلي للحمولات المستخرجة للكشف عن C2 والتجسس والثبات

---

## 🏗️ هيكل المشروع

</div>

```
JiaguSentinel/
├── main.py                 # الموجّه الذكي (CLI/GUI)
├── core/
│   ├── static_engine.py    # تحليل الانتروبيا، LIEF، YARA، كسر XOR
│   ├── dynamic_engine.py   # حقن Frida، تجاوز المضاد، فحص الذاكرة
│   └── adb_manager.py      # ADB ذاتي الإصلاح، كشف المعمارية، نشر Frida
├── analytics/
│   ├── malware_scorer.py   # أكثر من 40 نمط API مشبوه، تسجيل التهديدات (0-100)
│   └── report_gen.py       # تقارير JSON و Markdown الجنائية
├── ui/
│   ├── gui_main.py         # واجهة CustomTkinter ذات تبويبات بوضع ليلي
│   └── cli_main.py         # CLI احترافي بـ Rich + Click
├── payloads/
│   └── dex_dump.js         # عميل Frida محسّن بخطافات ART
├── rules/                  # قواعد YARA مخصصة (اختياري)
├── requirements.txt
└── README.md
```

<div dir="rtl">

---

## ⚡ البدء السريع

### المتطلبات الأساسية
- Python 3.10 أو أحدث  
- جهاز Android مع وصول **root** (للمحرك الديناميكي)  
- ADB مثبّت وضمن PATH  
- `frida-server` يتوافق مع معمارية جهازك  

### التثبيت

</div>

```bash
git clone https://github.com/yourrepo/JiaguSentinel.git
cd JiaguSentinel
pip install -r requirements.txt
```

<div dir="rtl">

### الاستخدام

#### وضع الواجهة الرسومية (الافتراضي)

</div>

```bash
python main.py
```

<div dir="rtl">

#### وضع سطر الأوامر

</div>

```bash
# التحليل الثابت
python main.py --cli scan path/to/suspicious.apk

# التفريغ الديناميكي (يتطلب جهازًا مُجذَّرًا + frida-server)
python main.py --cli dump com.suspicious.app

# تسجيل البرمجيات الخبيثة على DEX المستخرج
python main.py --cli analyze unpacked_output/extracted.dex

# توليد تقرير جنائي
python main.py --cli report path/to/suspicious.apk -f both

# معلومات الجهاز المتصل
python main.py --cli device

# عرض حمولات Frida المتاحة
python main.py --cli payloads

# إخراج JSON لبيئات CI/CD
python main.py --cli --json-output scan suspicious.apk
```

---

<div dir="rtl">

## 🔬 تفاصيل المحركات

### المحرك الثابت

| الميزة | الوصف |
|--------|-------|
| **فحص توقيعات DEX** | أنماط سحرية متعددة الإصدارات (v035–v041) مع التحقق من الرأس |
| **خريطة حرارة الانتروبيا** | انتروبيا شانون على مستوى الكتلة لتحديد المناطق المشفرة |
| **تحليل ELF بـ LIEF** | انتروبيا الأقسام، جدول الرموز، فحص الإعادة في `libjiagu*.so` |
| **فك ضغط متعدد الطبقات** | تتالي zlib ← gzip ← LZMA على الكتل عالية الانتروبيا |
| **كسر XOR بالقوة الغاشمة** | استعادة مفتاح بايت واحد للحمولات المشفرة بـ XOR |
| **مطابقة YARA** | فحص قواعد مخصصة لتوقيعات أدوات الحزم والبرمجيات الخبيثة |

### المحرك الديناميكي

| الميزة | الوصف |
|--------|-------|
| **مضاد للكشف عن Frida** | خطافات على `open`, `strstr`, `access`, `fopen`, `connect` |
| **فاحص DEX في الذاكرة** | يفحص جميع مناطق الذاكرة القابلة للقراءة بحثًا عن DEX |
| **خطاف منشئ ART** | يعترض `DexFile::OpenMemory` للاستخراج المبكر |
| **InMemoryDexClassLoader** | خطاف Java لتحميل DEX الخالي من الملفات |
| **إعادة الفحص الدوري** | يلتقط DEX المفكوك متأخرًا بفترات قابلة للضبط |
| **استعادة الجلسة** | إعادة محاولة تلقائية عند أخطاء النقل مع تقارير الأعطال |

### محرك تسجيل البرمجيات الخبيثة

| الفئة | أمثلة | نطاق الوزن |
|-------|--------|-------------|
| **تسريب البيانات** | SmsManager, sendTextMessage, ContentResolver | 4.0–9.0 |
| **التجسس** | Camera, AudioRecord, AccessibilityService | 4.0–9.0 |
| **تنفيذ الكود** | Runtime.exec, DexClassLoader, InMemoryDexClassLoader | 6.0–10.0 |
| **الثبات على الجهاز** | RECEIVE_BOOT_COMPLETED, DeviceAdminReceiver | 3.0–10.0 |
| **شبكة / C2** | Socket, WebSocket, DatagramSocket | 3.0–6.0 |
| **التمويه والتهرب** | isDebuggerConnected, خصائص Build | 2.0–7.0 |

---

## 🧩 توسيع JiaguSentinel

### إضافة حمولات Frida جديدة

</div>

```javascript
// payloads/my_custom_hook.js
'use strict';
Java.perform(function() {
    // خطاف مخصص هنا
    send({type: "dex_scan", results: [], total: 0});
});
```

<div dir="rtl">

ضع الملف في مجلد `payloads/` — ستظهر تلقائيًا في القائمة المنسدلة بالواجهة الرسومية وفي أوامر CLI.

### إضافة وحدات تحليل

</div>

```python
# analytics/my_analyzer.py
class MyAnalyzer:
    def analyze(self, dex_path: str) -> dict:
        return {"findings": [...]}
```

<div dir="rtl">

### إضافة قواعد YARA

ضع ملفات `.yar` في مجلد `rules/` — يتم تحميلها تلقائيًا بواسطة المحرك الثابت.

---

## ⚠️ إخلاء المسؤولية القانونية

> **تم تطوير JiaguSentinel Pro للاستخدام في البحث الأمني المرخص، وتحليل البرمجيات الخبيثة، والأغراض التعليمية فقط.**
>
> لا تستخدم هذه الأداة لتجاوز الحماية في تطبيقات لا تمتلكها أو لم تحصل على إذن صريح لتحليلها. لا يتحمل المؤلفون أي مسؤولية عن إساءة الاستخدام.
>
> التزم دائمًا بالقوانين والأنظمة المعمول بها وشروط الخدمة.

---

## 📜 الترخيص

هذا المشروع مرخص بموجب **ترخيص MIT**. راجع ملف [LICENSE](LICENSE) للتفاصيل.

---

## 🤝 المساهمة

نرحب بمساهماتك! المجالات التي نحتاج فيها إلى المساعدة:

- [ ] قواعد YARA جديدة لمتغيرات أدوات الحزم الناشئة
- [ ] حمولات Frida مخصصة لأنظمة حماية محددة
- [ ] وحدات تحليل إضافية (تحليل حركة الشبكة، مقارنة APK)
- [ ] دعم متعدد اللغات في الواجهة الرسومية
- [ ] اختبارات وحدات وخط أنابيب CI/CD

يُرجى فتح issue أو PR على GitHub.

---

<div align="center">

**صُنع لمجتمع أبحاث الأمن.**

*إذا أفادك JiaguSentinel في بحثك، فكر في إضافة نجمة للمستودع ⭐*

</div>

</div>
