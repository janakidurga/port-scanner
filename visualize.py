import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import ListedColormap

# Function to visualize open and closed ports with bar chart and pie chart
def visualize_results(open_ports, closed_ports):
    # Create two columns side by side
    col1, col2 = st.columns(2)

    # Bar chart in the first column
    with col1:
        if open_ports:
            st.write("Open Ports Bar Chart:")
            st.bar_chart(open_ports)
        else:
            st.write("No open ports found.")

    # Pie chart in the second column
    with col2:
        if open_ports or closed_ports:
            st.write("Open vs Closed Ports Pie Chart:")
            
            # Create data for the pie chart
            labels = ['Open Ports', 'Closed Ports']
            sizes = [len(open_ports), len(closed_ports)]
            colors = ['#4CAF50', '#FF5722']  # Green for open, Red for closed
            
            # Create the pie chart
            fig, ax = plt.subplots()
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.axis('equal')  # Equal aspect ratio ensures that the pie is drawn as a circle.
            
            st.pyplot(fig)
        else:
            st.write("No port data available.")

def visualize_subnet_results(active_hosts, total_hosts, scanned_ips):
    st.markdown("### 🌐 Subnet Scan Results")

    st.write(f"**Total Hosts Scanned:** {total_hosts}")
    st.write(f"**Active Hosts Found:** {len(active_hosts)}")

    # 📊 Bar Chart
    st.write("#### 📊 Active vs Inactive Hosts (Bar Chart)")
    ip_labels = [str(ip) for ip in scanned_ips]
    status_list = [1 if str(ip) in active_hosts else 0 for ip in ip_labels]

    # Set bar height for inactive hosts to 0.2 (so orange bars are visible)
    bar_heights = [1 if status == 1 else 0.2 for status in status_list]
    bar_colors = ['green' if status == 1 else 'orange' for status in status_list]

    fig_bar, ax_bar = plt.subplots(figsize=(10, 2))
    ax_bar.bar(ip_labels, bar_heights, color=bar_colors)
    ax_bar.set_xticks(range(len(ip_labels)))
    ax_bar.set_xticklabels(ip_labels, rotation=90, fontsize=6)
    ax_bar.set_yticks([])
    ax_bar.set_title("Active Hosts (Green) vs Inactive (Orange)")

    # Legend for clarity
    import matplotlib.patches as mpatches
    green_patch = mpatches.Patch(color='green', label='Active')
    orange_patch = mpatches.Patch(color='orange', label='Inactive')
    ax_bar.legend(handles=[green_patch, orange_patch])

    st.pyplot(fig_bar)

    # 🧭 Heatmap
    st.write("#### 🧭 Heatmap View (Grid Overview)")
    cols = 6
    rows = int(np.ceil(len(scanned_ips) / cols))
    heatmap_data = np.zeros((rows, cols))

    for idx, ip in enumerate(scanned_ips):
        r = idx // cols
        c = idx % cols
        heatmap_data[r][c] = 1 if str(ip) in active_hosts else 0

    fig_heat, ax_heat = plt.subplots(figsize=(cols, rows))
    from matplotlib.colors import ListedColormap
    cmap = ListedColormap(['orange', 'green'])  # 0 = Inactive (orange), 1 = Active (green)
    ax_heat.imshow(heatmap_data, cmap=cmap, vmin=0, vmax=1)

    # Annotate each square with the IP
    for idx, ip in enumerate(scanned_ips):
        r = idx // cols
        c = idx % cols
        ax_heat.text(c, r, str(ip), ha='center', va='center', fontsize=6, color='black')

    ax_heat.set_xticks([])
    ax_heat.set_yticks([])
    ax_heat.set_title("Heatmap of IP Activity (Green = Active, Orange = Inactive)")
    st.pyplot(fig_heat)

    # ✅ Active Hosts List (moved to the bottom)
    if active_hosts:
        st.success("### ✅ Active Hosts:")
        for ip in active_hosts:
            st.markdown(f"- {ip}")
    else:
        st.warning("No active hosts found.")
