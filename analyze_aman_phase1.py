import xml.etree.ElementTree as ET
import os

def parse_delay(delay_str):
    s = delay_str.replace('+', '').strip()
    if s.endswith('ms'):
        return float(s[:-2]) * 1e6
    elif s.endswith('ns'):
        return float(s[:-2])
    elif s.endswith('s') and not s.endswith('ns') and not s.endswith('ms'):
        return float(s[:-1]) * 1e9
    return 0.0

def analyze(xml_file, label, sim_time=300.0):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"  خطأ في {xml_file}: {e}")
        return None

    # [تعديل هندسي هام]: استخراج معرفات التدفق (Flow IDs) الخاصة بتطبيقنا فقط (المنفذ 5000)
    # لتجاهل رسائل التوجيه (AODV) التي تشوه حسابات جودة الخدمة
    valid_flows = set()
    for classifier in root.findall('.//Ipv4FlowClassifier/Flow'):
        if classifier.get('destinationPort') == '5000':
            valid_flows.add(classifier.get('flowId'))

    tx = rx = 0
    total_delay = total_bytes = 0.0

    # البحث عن التدفقات إما داخل FlowStats أو مباشرة
    flows = root.findall('.//FlowStats/Flow')
    if not flows:
        flows = root.findall('.//Flow')

    for flow in flows:
        flow_id = flow.get('flowId')
        # حساب الإحصائيات فقط لتدفقات البيانات الفعلية
        if flow_id in valid_flows:
            tx          += int(flow.get('txPackets', 0))
            rx          += int(flow.get('rxPackets', 0))
            total_delay += parse_delay(flow.get('delaySum', '0ns'))
            total_bytes += float(flow.get('rxBytes', 0))

    pdr        = (rx / tx * 100)            if tx > 0 else 0.0
    avg_delay  = (total_delay / rx / 1e9)   if rx > 0 else 0.0
    throughput = (total_bytes * 8 / sim_time / 1e3) if sim_time > 0 else 0.0

    return {
        'label':      label,
        'tx':         tx,
        'rx':         rx,
        'pdr':        pdr,
        'delay':      avg_delay,
        'throughput': throughput
    }

def read_energy(filename):
    try:
        with open(filename, 'r') as f:
            return float(f.read().strip())
    except:
        return None

def print_table(results):
    print("\n" + "="*72)
    print("        نتائج محاكاة شبكة أمان الطوارئ — AODV/MANET")
    print("="*72)
    print(f"  {'السيناريو':<32} {'PDR%':>7} {'تأخير(s)':>11} {'Throughput(kbps)':>16}")
    print("-"*72)
    for r in results:
        print(f"  {r['label']:<32} {r['pdr']:>7.2f}"
              f" {r['delay']:>11.5f} {r['throughput']:>16.2f}")
    print("="*72)

    if len(results) < 4:
        print("\n  تحذير: بعض ملفات XML غير متوفرة\n")
        return

    r0, r1, r2, r3 = results[0], results[1], results[2], results[3]

    print("\n  [ تكلفة طبقة الأمان ]")
    print(f"    PDR تغيّر بـ          : {r1['pdr']-r0['pdr']:+.2f}%")
    print(f"    التأخير تغيّر بـ       : {r1['delay']-r0['delay']:+.5f} ثانية")
    print(f"    Throughput تغيّر بـ    : {r1['throughput']-r0['throughput']:+.2f} kbps")

    print("\n  [ تأثير هجوم Blackhole ]")
    print(f"    PDR بدون هجوم         : {r0['pdr']:.2f}%")
    print(f"    PDR مع هجوم           : {r2['pdr']:.2f}%")
    print(f"    خسارة بسبب الهجوم      : {r2['pdr']-r0['pdr']:+.2f}%")

    print("\n  [ فاعلية IDS ]")
    print(f"    PDR مع هجوم بدون IDS  : {r2['pdr']:.2f}%")
    print(f"    PDR مع هجوم + IDS     : {r3['pdr']:.2f}%")
    print(f"    تحسن بعد الكشف        : {r3['pdr']-r2['pdr']:+.2f}%")

    print("\n  [ استهلاك الطاقة — من المحاكاة الفعلية ]")
    energy_map = [
        ("energy_aodv.txt",      "AODV عادي"),
        ("energy_secure.txt",    "AODV + أمان"),
        ("energy_blackhole.txt", "AODV + Blackhole"),
        ("energy_secure_bh.txt", "AODV + أمان + IDS"),
    ]
    base_pct = None
    for fname, lbl in energy_map:
        pct = read_energy(fname)
        if pct is not None:
            diff = f"  ({pct-base_pct:+.2f}%)" if base_pct is not None else ""
            print(f"    {lbl:<25}: {pct:.2f}%{diff}")
            if base_pct is None:
                base_pct = pct
        else:
            print(f"    {lbl:<25}: غير متوفر بعد")

    print("="*72 + "\n")

scenarios = [
    ("aman-flow-aodv.xml",                  "AODV (بدون أمان)"),
    ("aman-flow-aodv-secure.xml",           "AODV + أمان"),
    ("aman-flow-aodv-blackhole.xml",        "AODV + Blackhole"),
    ("aman-flow-aodv-secure-blackhole.xml", "AODV + أمان + Blackhole IDS"),
]

results = []
for xml_file, label in scenarios:
    if os.path.exists(xml_file):
        r = analyze(xml_file, label)
        if r:
            results.append(r)
    else:
        print(f"  ملف غير موجود: {xml_file}")

if results:
    print_table(results)
else:
    print("لا توجد نتائج — شغّل المحاكاة أولاً")
