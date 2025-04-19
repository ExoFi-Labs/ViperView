import sys
import os
import json
import humanize
import pandas as pd
from pathlib import Path
import argparse
import pkg_resources
from datetime import datetime
import uuid

def get_package_sizes():
    packages = []
    for dist in pkg_resources.working_set:
        try:
            location = Path(dist.location) / dist.project_name.replace("-", "_")
            if not location.exists():
                location = Path(dist.location) / dist.project_name.lower()
            if location.exists():
                size = 0
                for dirpath, _, filenames in os.walk(location):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        if os.path.isfile(fp):
                            size += os.path.getsize(fp)
                packages.append({
                    "name": dist.project_name,
                    "version": dist.version,
                    "size_bytes": size,
                    "location": str(location)
                })
        except Exception as e:
            print(f"[!] Error reading {dist.project_name}: {e}")
    return packages

def generate_cyclonedx_sbom(packages):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [
                {
                    "vendor": "pysleuth",
                    "name": "pysleuth Package Analyzer",
                    "version": "1.0.0"
                }
            ]
        },
        "components": []
    }
    
    for pkg in packages:
        component = {
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name']}@{pkg['version']}",
            "properties": [
                {
                    "name": "size",
                    "value": str(pkg["size_bytes"])
                },
                {
                    "name": "location",
                    "value": pkg["location"]
                }
            ]
        }
        sbom["components"].append(component)
    
    return sbom

def format_text_output(packages):
    output = "# Python Packages SBOM\n"
    output += f"# Generated: {datetime.now().isoformat()}\n"
    output += "# Format: name | version | size | location\n"
    output += "-" * 80 + "\n"
    
    for pkg in sorted(packages, key=lambda x: x["name"].lower()):
        size = humanize.naturalsize(pkg["size_bytes"], binary=True)
        output += f"{pkg['name']} | {pkg['version']} | {size} | {pkg['location']}\n"
    
    return output

def analyze_packages(output_format='text', output_file=None):
    packages = get_package_sizes()
    
    # Calculate total size
    total_size = sum(pkg["size_bytes"] for pkg in packages)
    total_packages = len(packages)
    
    if output_format == 'json':
        output = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_packages": total_packages,
                "total_size_bytes": total_size,
                "total_size_human": humanize.naturalsize(total_size, binary=True)
            },
            "packages": packages
        }
    elif output_format == 'cyclonedx':
        output = generate_cyclonedx_sbom(packages)
    else:  # text format
        output = format_text_output(packages)
    
    if output_file:
        with open(output_file, 'w') as f:
            if isinstance(output, (dict, list)):
                json.dump(output, f, indent=2)
            else:
                f.write(output)
        print(f"\n💾 Output written to: {output_file}")
    else:
        if isinstance(output, (dict, list)):
            print(json.dumps(output, indent=2))
        else:
            print(output)
    
    # Always print summary to stderr
    print(f"\n📦 Summary:", file=sys.stderr)
    print(f"Total packages: {total_packages}", file=sys.stderr)
    print(f"Total size: {humanize.naturalsize(total_size, binary=True)}", file=sys.stderr)
    print(f"Average size: {humanize.naturalsize(total_size/total_packages, binary=True)}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Python Package Analyzer - Generate package inventory and SBOM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch GUI interface
  %(prog)s --gui
  
  # Generate text format output
  %(prog)s
  
  # Generate JSON SBOM and save to file
  %(prog)s --format json --output packages.json
  
  # Generate CycloneDX SBOM
  %(prog)s --format cyclonedx --output sbom.json
"""
    )
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    parser.add_argument("--format", choices=['text', 'json', 'cyclonedx'], 
                       default='text', help="Output format (default: text)")
    parser.add_argument("--output", type=str, help="Output file path")
    args = parser.parse_args()
    
    if args.gui:
        # Import GUI components only if needed
        from PyQt5.QtWidgets import (
            QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget,
            QTableWidgetItem, QLabel, QFileDialog, QLineEdit, QHeaderView
        )
        from PyQt5.QtWebEngineWidgets import QWebEngineView
        from PyQt5.QtCore import Qt
        import plotly.express as px
        
        class pysleuth(QWidget):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("🐍 pysleuth: Python Package Analyzer")
                self.resize(1000, 800)
                self.setStyleSheet("""
                    QWidget {
                        background-color: #1e1e2f;
                        color: #eee;
                        font-family: 'Segoe UI', sans-serif;
                    }
                    QPushButton {
                        background-color: #3a3a5c;
                        color: white;
                        padding: 8px;
                        border-radius: 4px;
                    }
                    QLineEdit {
                        padding: 6px;
                        background: #2b2b3d;
                        border: 1px solid #555;
                        border-radius: 4px;
                        color: #eee;
                    }
                """)

                self.data = pd.DataFrame(get_package_sizes())
                self.data["size_mb"] = self.data["size_bytes"] / (1024 * 1024)
                self.data["pretty_size"] = self.data["size_bytes"].apply(lambda x: humanize.naturalsize(x, binary=True))

                self.init_ui()

            def init_ui(self):
                layout = QVBoxLayout()

                self.stats_label = QLabel()
                self.stats_label.setAlignment(Qt.AlignCenter)
                layout.addWidget(self.stats_label)

                self.search_box = QLineEdit()
                self.search_box.setPlaceholderText("🔍 Filter packages by name...")
                self.search_box.textChanged.connect(self.filter_table)
                layout.addWidget(self.search_box)

                self.table = QTableWidget()
                self.table.setColumnCount(4)
                self.table.setHorizontalHeaderLabels(["Package", "Version", "Size", "Location"])
                self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
                layout.addWidget(self.table)

                # Add export buttons
                export_layout = QVBoxLayout()
                self.export_csv_btn = QPushButton("📥 Export to CSV")
                self.export_csv_btn.clicked.connect(self.export_to_csv)
                self.export_sbom_btn = QPushButton("📦 Export SBOM (CycloneDX)")
                self.export_sbom_btn.clicked.connect(self.export_to_sbom)
                export_layout.addWidget(self.export_csv_btn)
                export_layout.addWidget(self.export_sbom_btn)
                layout.addLayout(export_layout)

                self.plot_view = QWebEngineView()
                layout.addWidget(self.plot_view)

                self.setLayout(layout)

                self.populate_table(self.data)
                self.update_stats()
                self.show_plot()

            def populate_table(self, df):
                self.table.setRowCount(0)
                for index, row in df.iterrows():
                    self.table.insertRow(index)
                    self.table.setItem(index, 0, QTableWidgetItem(row["name"]))
                    self.table.setItem(index, 1, QTableWidgetItem(row["version"]))
                    self.table.setItem(index, 2, QTableWidgetItem(row["pretty_size"]))
                    self.table.setItem(index, 3, QTableWidgetItem(row["location"]))

            def update_stats(self):
                total = humanize.naturalsize(self.data["size_bytes"].sum(), binary=True)
                avg = humanize.naturalsize(self.data["size_bytes"].mean(), binary=True)
                count = len(self.data)
                self.stats_label.setText(f"📦 {count} packages | 💾 Total: {total} | 🧮 Average: {avg}")

            def export_to_csv(self):
                path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
                if path:
                    self.data.to_csv(path, index=False)

            def export_to_sbom(self):
                path, _ = QFileDialog.getSaveFileName(self, "Export SBOM", "", "JSON Files (*.json)")
                if path:
                    packages = self.data.to_dict('records')
                    sbom = generate_cyclonedx_sbom(packages)
                    with open(path, 'w') as f:
                        json.dump(sbom, f, indent=2)

            def filter_table(self):
                text = self.search_box.text().lower()
                filtered = self.data[self.data["name"].str.lower().str.contains(text)]
                self.populate_table(filtered)
                self.update_plot(filtered)

            def show_plot(self):
                fig = px.bar(self.data.sort_values("size_mb", ascending=False).head(20),
                             x="size_mb", y="name", orientation="h",
                             hover_data=["version", "pretty_size"],
                             color="size_mb", color_continuous_scale="Plasma")
                fig.update_layout(
                    height=500,
                    paper_bgcolor="#1e1e2f",
                    plot_bgcolor="#1e1e2f",
                    font_color="#eee",
                    xaxis_title="Size (MB)",
                    yaxis_title="Package",
                    title="Top 20 Largest Pip Packages"
                )
                html = fig.to_html(include_plotlyjs='cdn')
                self.plot_view.setHtml(html)

            def update_plot(self, df):
                fig = px.bar(df.sort_values("size_mb", ascending=False).head(20),
                             x="size_mb", y="name", orientation="h",
                             hover_data=["version", "pretty_size"],
                             color="size_mb", color_continuous_scale="Plasma")
                fig.update_layout(
                    height=500,
                    paper_bgcolor="#1e1e2f",
                    plot_bgcolor="#1e1e2f",
                    font_color="#eee",
                    xaxis_title="Size (MB)",
                    yaxis_title="Package"
                )
                html = fig.to_html(include_plotlyjs='cdn')
                self.plot_view.setHtml(html)

        app = QApplication(sys.argv)
        viewer = pysleuth()
        viewer.show()
        sys.exit(app.exec_())
    else:
        analyze_packages(args.format, args.output)

if __name__ == "__main__":
    main()
