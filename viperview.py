import sys
import os
import humanize
import pandas as pd
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QFileDialog, QLineEdit, QHeaderView
)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import Qt
import plotly.express as px
import pkg_resources

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

class ViperView(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🐍 ViperView: Python Package Analyzer")
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

        self.export_btn = QPushButton("📥 Export to CSV")
        self.export_btn.clicked.connect(self.export_to_csv)
        layout.addWidget(self.export_btn)

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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = ViperView()
    viewer.show()
    sys.exit(app.exec_())
