import matplotlib.pyplot as plt

# البيانات المستخرجة من المحاكاة الفعلية
scenarios = ['AODV Base', 'AODV+Security', 'AODV+Blackhole', 'AODV+Sec+IDS']
pdr = [74.17, 72.22, 73.82, 68.93]
throughput = [48.25, 47.04, 48.03, 44.90]
delay = [0.04988 * 1000, 0.05718 * 1000, 0.05375 * 1000, 0.06628 * 1000] # ms
energy = [9.19, 10.22, 9.04, 11.68]

# إعداد الشكل العام للرسومات
fig, axs = plt.subplots(2, 2, figsize=(12, 10))
colors = ['#2b5c8f', '#2b8f5c', '#d9534f', '#8e44ad']

# 1. PDR Graph
axs[0, 0].bar(scenarios, pdr, color=colors)
axs[0, 0].set_title('Packet Delivery Ratio (PDR %)')
axs[0, 0].set_ylim(0, 100)
for i, v in enumerate(pdr):
    axs[0, 0].text(i, v + 2, f"{v}%", ha='center', fontweight='bold')

# 2. Throughput Graph
axs[0, 1].bar(scenarios, throughput, color=colors)
axs[0, 1].set_title('Throughput (kbps)')
axs[0, 1].set_ylim(0, 60)
for i, v in enumerate(throughput):
    axs[0, 1].text(i, v + 1, f"{v}", ha='center', fontweight='bold')

# 3. Delay Graph
axs[1, 0].bar(scenarios, delay, color=colors)
axs[1, 0].set_title('Average End-to-End Delay (ms)')
axs[1, 0].set_ylim(0, 80)
for i, v in enumerate(delay):
    axs[1, 0].text(i, v + 1, f"{v:.1f}ms", ha='center', fontweight='bold')

# 4. Energy Consumption Graph
axs[1, 1].bar(scenarios, energy, color=colors)
axs[1, 1].set_title('Energy Consumption (%)')
axs[1, 1].set_ylim(0, 20)
for i, v in enumerate(energy):
    axs[1, 1].text(i, v + 0.3, f"{v}%", ha='center', fontweight='bold')

# تحسين المظهر
for ax in axs.flat:
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    ax.set_xticklabels(scenarios, rotation=15, ha='right')

plt.tight_layout()
plt.savefig('aman_simulation_results.png', dpi=300)
print("\n تم حفظ المخططات البيانية بنجاح في الملف: aman_simulation_results.png\n")
