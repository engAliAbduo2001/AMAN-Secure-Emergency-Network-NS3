import matplotlib.pyplot as plt

scenarios = ['AODV Base', 'AODV+Sec', 'Blackhole', 'BH+Sec', 'Grayhole', 'GH+Sec']
pdr = [75.16, 72.22, 73.82, 68.59, 76.50, 71.10]
throughput = [39.47, 47.04, 38.77, 35.96, 49.30, 46.15]
delay = [36.69, 57.18, 37.20, 59.12, 51.40, 60.80]
energy = [5.87, 10.22, 6.75, 9.29, 5.87, 8.03]

fig, axs = plt.subplots(2, 2, figsize=(14, 10))
colors = ['#2b5c8f', '#2b8f5c', '#d9534f', '#8e44ad', '#e67e22', '#16a085']

# Packet Delivery Ratio
axs[0, 0].bar(scenarios, pdr, color=colors)
axs[0, 0].set_title('Packet Delivery Ratio (PDR %)', fontweight='bold')
axs[0, 0].set_ylim(0, 100)
for i, v in enumerate(pdr):
    axs[0, 0].text(i, v + 2, f"{v:.1f}%", ha='center', fontweight='bold', fontsize=9)

# Throughput
axs[0, 1].bar(scenarios, throughput, color=colors)
axs[0, 1].set_title('Throughput (kbps)', fontweight='bold')
axs[0, 1].set_ylim(0, 60)
for i, v in enumerate(throughput):
    axs[0, 1].text(i, v + 1, f"{v:.1f}", ha='center', fontweight='bold', fontsize=9)

# End-to-End Delay
axs[1, 0].bar(scenarios, delay, color=colors)
axs[1, 0].set_title('Average End-to-End Delay (ms)', fontweight='bold')
axs[1, 0].set_ylim(0, 80)
for i, v in enumerate(delay):
    axs[1, 0].text(i, v + 1.5, f"{v:.1f}ms", ha='center', fontweight='bold', fontsize=9)

# Energy Consumption
axs[1, 1].bar(scenarios, energy, color=colors)
axs[1, 1].set_title('Energy Consumption (%)', fontweight='bold')
axs[1, 1].set_ylim(0, 20)
for i, v in enumerate(energy):
    axs[1, 1].text(i, v + 0.3, f"{v:.1f}%", ha='center', fontweight='bold', fontsize=9)

for ax in axs.flat:
    ax.grid(axis='y', linestyle='--', alpha=0.6)
    ax.set_xticks(range(len(scenarios)))
    ax.set_xticklabels(scenarios, rotation=20, ha='right', fontsize=9.5)

plt.tight_layout()
plt.savefig('aman_simulation_results.png', dpi=300)
plt.close()
print("\n[✓] تم حفظ الرسم البياني بنجاح إلى الملف: aman_simulation_results.png\n")
