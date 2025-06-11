import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk  # Import ttk for Treeview
from PIL import Image, ImageTk
import os
from threading import Thread
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import pyshark
import nest_asyncio
from collections import Counter
import math

# Apply nest_asyncio to patch the event loop
nest_asyncio.apply()

# Set CustomTkinter appearance and theme
ctk.set_appearance_mode("dark")  # Dark mode
ctk.set_default_color_theme("dark-blue")  # Dark-blue accents

class PCAPAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NET TRACER")
        self.root.geometry("1000x700")

        # Variables
        self.pcap_file = None
        self.anomaly_data = None
        self.histogram_path = "anomaly_detection_results.png"
        self.scatter_path = "cluster_visualization.png"

        # GUI Elements
        self.create_widgets()

    def create_widgets(self):
        # Title
        title_label = ctk.CTkLabel(self.root, text="NET TRACER", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        # File Selection Frame
        file_frame = ctk.CTkFrame(self.root)
        file_frame.pack(pady=10, padx=20, fill="x")
        
        file_label = ctk.CTkLabel(file_frame, text="Select PCAP File:", font=("Arial", 14))
        file_label.pack(side="left", padx=10)
        
        self.file_entry = ctk.CTkEntry(file_frame, width=400, font=("Arial", 12))
        self.file_entry.pack(side="left", padx=10)
        
        browse_button = ctk.CTkButton(file_frame, text="Browse", command=self.browse_file, width=100)
        browse_button.pack(side="left", padx=10)

        # Analyze Button
        analyze_button = ctk.CTkButton(self.root, text="Analyze PCAP", command=self.run_analysis_thread,
                                      font=("Arial", 14), width=200, height=40)
        analyze_button.pack(pady=20)

        # Progress Label
        self.progress_label = ctk.CTkLabel(self.root, text="", font=("Arial", 12))
        self.progress_label.pack(pady=10)

        # Tabs for Results
        self.notebook = ctk.CTkTabview(self.root, height=500)
        self.notebook.pack(pady=10, padx=20, fill="both", expand=True)

        # Anomaly Table Tab
        self.table_tab = self.notebook.add("Anomaly Report")
        
        # Images Tab
        self.image_tab = self.notebook.add("Visualizations")

    def browse_file(self):
        self.pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if self.pcap_file:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, self.pcap_file)

    def run_analysis_thread(self):
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file first!")
            return
        self.progress_label.configure(text="Analyzing PCAP file... Please wait.")
        Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        try:
            # Load packets using pyshark
            cap = pyshark.FileCapture(self.pcap_file, display_filter="tcp", tshark_path="C:\\Program Files\\Wireshark\\tshark.exe")
            packets, ip_counts = self.extract_packet_features(cap)

            if not packets:
                self.progress_label.configure(text="No valid packets found in the PCAP file.")
                return

            # Create a pandas DataFrame
            columns = ["time_in_seconds", "src_ip", "dst_ip", "src_port", "dst_port", "payload_size", "entropy", "info", "raw_payload"]
            df = pd.DataFrame(packets, columns=columns)

            # Feature encoding
            encoded_packets = self.encode_features(packets, ip_counts)
            X = np.array(encoded_packets, dtype=float)
            X = np.nan_to_num(X)

            if len(X) < 2:
                self.progress_label.configure(text="Not enough data points for clustering.")
                return

            # Clustering and anomaly detection
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            n_clusters = self.find_optimal_clusters(X_scaled)
            kmeans = KMeans(n_clusters=n_clusters, max_iter=300, n_init=10, random_state=42)
            kmeans.fit(X_scaled)

            distances = np.min(np.sqrt(((X_scaled[:, np.newaxis, :] - kmeans.cluster_centers_[np.newaxis, :, :]) ** 2).sum(axis=2)), axis=1)
            labels = kmeans.labels_
            cluster_sizes = np.bincount(labels)
            threshold = np.percentile(distances, 95)
            small_cluster_threshold = 5
            anomalies = np.where((distances > threshold) | (cluster_sizes[labels] < small_cluster_threshold))[0]
            valid_anomalies = [idx for idx in anomalies if idx < len(packets)]

            # Prepare anomaly table data
            self.anomaly_data = []
            headers = ["Packet #", "Time (s)", "Source IP", "Dest IP", "Src Port", "Dst Port", "Payload (bytes)", "IP Freq", "Entropy", "Info", "Raw Payload", "Distance"]
            for idx in valid_anomalies:
                pkt = df.iloc[idx]
                self.anomaly_data.append([
                    idx,
                    f"{pkt['time_in_seconds']:.6f}",
                    pkt['src_ip'],
                    pkt['dst_ip'],
                    pkt['src_port'],
                    pkt['dst_port'],
                    pkt['payload_size'],
                    ip_counts.get(pkt['src_ip'], 0),
                    f"{pkt['entropy']:.2f}",
                    pkt['info'],
                    pkt['raw_payload'][:100] + ('...' if len(pkt['raw_payload']) > 100 else ''),
                    f"{distances[idx]:.2f}"
                ])

            # Generate visualizations
            self.generate_visualizations(X, X_scaled, labels, valid_anomalies, distances, threshold)

            # Update GUI
            self.update_gui(len(valid_anomalies), len(X))

        except Exception as e:
            self.progress_label.configure(text=f"Error: {str(e)}")

    def extract_packet_features(self, cap):
        packets = []
        ip_counts = Counter()
        first_timestamp = None
        for i, packet in enumerate(cap):
            try:
                if not (hasattr(packet, 'tcp') and hasattr(packet, 'ip')):
                    continue
                absolute_timestamp = packet.sniff_time.timestamp()
                if first_timestamp is None:
                    first_timestamp = absolute_timestamp
                timestamp = float(absolute_timestamp - first_timestamp)
                src_ip = str(packet.ip.src)
                dst_ip = str(packet.ip.dst)
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                payload_size = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
                payload = bytes.fromhex(packet.tcp.payload.replace(':', '')) if hasattr(packet.tcp, 'payload') else b''
                entropy = float(-sum((c / len(payload)) * math.log2(c / len(payload))
                                    for c in Counter(payload).values())) if payload else 0.0
                ip_counts[src_ip] += 1
                info = str(packet.highest_layer)
                raw_payload = payload.decode('utf-8', errors='ignore')
                if src_ip is None or dst_ip is None:
                    continue
                packets.append((timestamp, src_ip, dst_ip, src_port, dst_port, payload_size, entropy, info, raw_payload))
            except Exception:
                continue
        cap.close()
        return packets, ip_counts

    def encode_features(self, packets, ip_counts):
        ip_dict, dst_ip_dict = {}, {}
        ip_counter, dst_ip_counter = [1], [1]
        encoded_packets = []
        for row in packets:
            encoded_row = (
                encode_feature(row[1], ip_dict, ip_counter),
                encode_feature(row[2], dst_ip_dict, dst_ip_counter),
                int(row[3]),
                int(row[4]),
                float(row[0]),
                int(row[5]),
                ip_counts.get(row[1], 0),
                float(row[6])
            )
            encoded_packets.append(encoded_row)
        return encoded_packets

    def find_optimal_clusters(self, X, max_k=10):
        if len(X) < 2:
            return 1
        scores = []
        for k in range(2, min(max_k, len(X) // 2)):
            kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
            labels = kmeans.fit_predict(X)
            scores.append(silhouette_score(X, labels))
        return scores.index(max(scores)) + 2 if scores else 2

    def generate_visualizations(self, X, X_scaled, labels, anomalies, distances, threshold):
        # Histogram
        plt.style.use('dark_background')
        plt.figure(figsize=(10, 6))
        plt.hist(distances, bins=50, color='blue', alpha=0.7)
        plt.axvline(threshold, color='red', linestyle='dashed', linewidth=2, label='Threshold')
        plt.xlabel("Distance from Cluster Center")
        plt.ylabel("Frequency")
        plt.title("Anomaly Detection Results")
        plt.legend()
        plt.savefig(self.histogram_path, bbox_inches='tight', facecolor='#212121')
        plt.close()

        # Scatter plot
        plt.figure(figsize=(10, 6))
        plt.scatter(X[:, 4], X[:, 3], c=labels, cmap='viridis', s=50, alpha=0.5)
        plt.scatter(X[anomalies, 4], X[anomalies, 3], c='red', marker='x', s=100, label='Anomalies')
        plt.xlabel("Time (seconds since capture start)")
        plt.ylabel("Destination Port")
        plt.title("Clusters and Anomalies")
        plt.legend()
        plt.savefig(self.scatter_path, bbox_inches='tight', facecolor='#212121')
        plt.close()

    def update_gui(self, anomaly_count, total_packets):
        # Update progress
        self.progress_label.configure(text=f"Analysis Complete: {anomaly_count} anomalies detected out of {total_packets} packets.")

        # Clear previous content
        for widget in self.table_tab.winfo_children():
            widget.destroy()
        for widget in self.image_tab.winfo_children():
            widget.destroy()

        # Anomaly Table with ttk.Treeview
        table_frame = ctk.CTkFrame(self.table_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        tree = ttk.Treeview(table_frame, columns=[f"col{i}" for i in range(12)], show="headings", height=15)
        headers = ["Packet #", "Time (s)", "Source IP", "Dest IP", "Src Port", "Dst Port", "Payload (bytes)", "IP Freq", "Entropy", "Info", "Raw Payload", "Distance"]
        for i, header in enumerate(headers):
            tree.heading(f"col{i}", text=header)
            tree.column(f"col{i}", width=100, anchor="center")
        for row in self.anomaly_data:
            tree.insert("", "end", values=row)
        
        # Style Treeview to match dark theme
        style = ttk.Style()
        style.theme_use("default")  # Use default theme as base
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[("selected", "#3a3a3a")])

        tree.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)

        # Images
        image_frame = ctk.CTkFrame(self.image_tab)
        image_frame.pack(fill="both", expand=True, padx=10, pady=10)
        for img_path in [self.histogram_path, self.scatter_path]:
            if os.path.exists(img_path):
                img = Image.open(img_path)
                img = img.resize((450, 300), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                label = ctk.CTkLabel(image_frame, image=photo, text="")
                label.image = photo  # Keep a reference
                label.pack(pady=10)

def encode_feature(value, feature_dict, counter):
    if value is None or value == "":
        return 0
    if value not in feature_dict:
        feature_dict[value] = counter[0]
        counter[0] += 1
    return feature_dict[value]

if __name__ == "__main__":
    root = ctk.CTk()
    app = PCAPAnalyzerApp(root)
    root.mainloop()