# NET TRACER

NET TRACER is a Python application with a GUI built using CustomTkinter for analyzing PCAP files. It performs network packet analysis, clustering, and anomaly detection using machine learning techniques. The application visualizes anomalies and clusters through histograms and scatter plots.

## Features

- Load and analyze PCAP files using pyshark
- Extract packet features (e.g., source/destination IPs, ports, payload size, entropy)
- Perform KMeans clustering and anomaly detection
- Display results in a tabular format and visualizations

## Requirements

- Python 3.8+
- Tshark (Wireshark) installed and accessible (ensure `tshark.exe` is in your system PATH or specify its path in the code)
- Required Python packages (listed in `requirements.txt`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/net-tracer.git
   cd net-tracer
   ```
2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Ensure Tshark is installed:
   - Download and install Wireshark from https://www.wireshark.org/
   - Add Tshark to your system PATH or update the `tshark_path` in the code to point to `tshark.exe`.

## Usage

1. Run the application:

   ```bash
   python net_tracer.py
   ```
2. Select a PCAP file using the "Browse" button.
3. Click "Analyze PCAP" to process the file.
4. View results in the "Anomaly Report" tab (table) and "Visualizations" tab (histogram and scatter plot).

## Project Structure

- `net_tracer.py`: Main application script containing the GUI and analysis logic.
- `requirements.txt`: List of Python dependencies.
- `README.md`: Project documentation.
- Output files:
  - `anomaly_detection_results.png`: Histogram of anomaly detection results.
  - `cluster_visualization.png`: Scatter plot of clusters and anomalies.

## Notes

- The application filters TCP packets for analysis.
- Anomaly detection uses KMeans clustering and a combination of distance-based and cluster-size-based thresholds.
- Visualizations are saved as PNG files and displayed in the GUI.
- Ensure sufficient memory and disk space for large PCAP files.

## License

This project is licensed under the MIT License. See the LICENSE file for details.