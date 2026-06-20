"""PyQt5 desktop application for extracting cryptographic hashes from files."""

import csv
import json
import os
import sys
from datetime import datetime, timedelta
from hashextractor.persistence.db import HashDatabase

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from hashextractor.extractor import HashExtractor


class ScanWorker(QObject):
    """Run hash extraction in a worker thread and emit GUI-safe signals."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    result_found = pyqtSignal(str, str, str, str)
    scan_finished = pyqtSignal(dict, int)
    scan_failed = pyqtSignal(str)

    def __init__(self, directory, hash_types=None):
        """Create a worker for the selected input directory."""
        QObject.__init__(self)
        self.directory = directory
        self.hash_types = hash_types

    def run(self):
        """Execute extraction and emit completion or failure signals."""
        try:
            extractor = HashExtractor(self.directory)
            results = extractor.extract(
                self.progress_updated.emit,
                self.status_updated.emit,
                self.result_found.emit,
                hash_types=self.hash_types,
            )
            self.scan_finished.emit(results, len(extractor.errors))
        except Exception as error:
            self.scan_failed.emit(str(error))


class pdfAnalysis(QDialog):
    """Main Cryptographic Hash Extractor application dialog."""

    def __init__(self):
        """Build the GUI, initialize state, and connect widget signals."""
        QDialog.__init__(self)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.scan_thread = None
        self.scan_worker = None
        self.scan_results = {}
        self._last_hash_types = set()

        main_layout = QVBoxLayout()
        content_layout = QHBoxLayout()
        controls_layout = QVBoxLayout()
        pdf_layout = QHBoxLayout()
        button_layout = QHBoxLayout()
        export_layout = QHBoxLayout()
        summary_layout = QGridLayout()
        header_layout = QVBoxLayout()

        config_group = QGroupBox("File Scan Configuration")
        config_layout = QVBoxLayout()
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        summary_group = QGroupBox("Scan Summary")

        self.dir = QLineEdit()
        self.chk_md5 = QCheckBox("MD5")
        self.chk_sha1 = QCheckBox("SHA1")
        self.chk_sha256 = QCheckBox("SHA256")
        self.chk_sha512 = QCheckBox("SHA512")
        self.progress = QProgressBar()
        self.status_label = QLabel("Ready")
        self.title_label = QLabel("Cryptographic Hash Extractor")
        self.subtitle_label = QLabel("Multi-Algorithm File Hash Analysis")
        self.version_label = QLabel("v0.5.1")
        self.date_label = QLabel(QDate.currentDate().toString("MMMM d, yyyy"))
        self.pdfs_scanned = QLabel("0")
        self.hashes_found = QLabel("0")
        self.skipped_files = QLabel("0")
        self.results_table = QTableWidget(0, 4)

        self.execute = QPushButton("Start Scan")
        self.clear = QPushButton("Clear Form")
        self.browse_pdf = QPushButton("Select Input Folder")
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_json_btn = QPushButton("Export JSON")
        self.scan_history_btn = QPushButton("Scan History")

        self.dir.setPlaceholderText("Select the directory containing files to scan")
        for chk in (self.chk_md5, self.chk_sha1, self.chk_sha256, self.chk_sha512):
            chk.setChecked(True)
        self.progress.setValue(0)
        self.progress.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 22px; font-weight: bold; color: #1a1a2e;")
        self.subtitle_label.setStyleSheet("font-size: 11px; color: #6c757d;")
        self.version_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        self.version_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #6c757d;")
        self.date_label.setAlignment(Qt.AlignRight | Qt.AlignTop)
        self.date_label.setStyleSheet("font-size: 10px; color: #6c757d;")
        self.export_csv_btn.setEnabled(False)
        self.export_json_btn.setEnabled(False)

        self.results_table.setHorizontalHeaderLabels(["Source File", "File Type", "Hash Type", "Hash Value"])
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        # Paths are long; elide the middle so the drive and filename stay visible.
        self.results_table.setTextElideMode(Qt.ElideMiddle)
        header = self.results_table.horizontalHeader()
        # All columns are user-resizable so any of them can be dragged wider.
        for col in range(self.results_table.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.Interactive)
        # Let the last column absorb leftover space so there's no trailing gap.
        header.setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 420)
        self.results_table.setColumnWidth(1, 90)
        self.results_table.setColumnWidth(2, 90)

        pdf_layout.addWidget(QLabel("Input Directory"))
        pdf_layout.addWidget(self.dir)
        pdf_layout.addWidget(self.browse_pdf)

        button_layout.addWidget(self.execute)
        button_layout.addWidget(self.clear)
        button_layout.addWidget(self.scan_history_btn)
        button_layout.addStretch()

        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_json_btn)
        export_layout.addStretch()

        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("Hash Types"))
        hash_layout.addWidget(self.chk_md5)
        hash_layout.addWidget(self.chk_sha1)
        hash_layout.addWidget(self.chk_sha256)
        hash_layout.addWidget(self.chk_sha512)
        hash_layout.addStretch()

        config_layout.addLayout(pdf_layout)
        config_layout.addLayout(hash_layout)
        config_layout.addWidget(QLabel("Progress"))
        config_layout.addWidget(self.progress)
        config_layout.addLayout(button_layout)
        config_layout.addLayout(export_layout)
        config_group.setLayout(config_layout)

        summary_layout.addWidget(QLabel("Files Scanned"), 0, 0)
        summary_layout.addWidget(self.pdfs_scanned, 0, 1)
        summary_layout.addWidget(QLabel("Hashes Found"), 1, 0)
        summary_layout.addWidget(self.hashes_found, 1, 1)
        summary_layout.addWidget(QLabel("Skipped Files"), 2, 0)
        summary_layout.addWidget(self.skipped_files, 2, 1)
        summary_layout.setColumnStretch(1, 1)
        summary_group.setLayout(summary_layout)

        controls_layout.addWidget(config_group)
        controls_layout.addWidget(summary_group)
        controls_layout.addStretch()

        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)

        content_layout.addLayout(controls_layout, 2)
        content_layout.addWidget(results_group, 3)

        header_left = QVBoxLayout()
        header_left.setSpacing(2)
        header_left.addWidget(self.title_label)
        header_left.addWidget(self.subtitle_label)

        header_right = QVBoxLayout()
        header_right.setSpacing(2)
        header_right.addWidget(self.version_label)
        header_right.addWidget(self.date_label)

        header_row = QHBoxLayout()
        header_row.addLayout(header_left)
        header_row.addStretch()
        header_row.addLayout(header_right)

        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("color: #dee2e6;")

        header_layout.addLayout(header_row)
        header_layout.addWidget(separator)
        main_layout.addLayout(header_layout)
        main_layout.addLayout(content_layout)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)
        self.setGeometry(200, 200, 1050, 400)
        self.setWindowTitle("Cryptographic Hash Extractor v0.5.1 (labgeek)")
        self.setFocus()

        self.execute.clicked.connect(self.search)
        self.clear.clicked.connect(self.clear_fields)
        self.browse_pdf.clicked.connect(self.browse_pdf_directory)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.export_json_btn.clicked.connect(self.export_json)
        self.scan_history_btn.clicked.connect(self.open_scan_history)

        if getattr(sys, 'frozen', False):
            _db_path = os.path.join(os.path.dirname(sys.executable), "hashextractor.db")
        else:
            # Go up one level from hashextractor/ to the project root
            _db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "hashextractor.db"
            )
        self.db = HashDatabase(_db_path)

    def browse_pdf_directory(self):
        """Open a folder picker and populate the input directory field."""
        directory = QFileDialog.getExistingDirectory(self, caption="Select Input Directory", directory=".")
        if directory:
            self.dir.setText(QDir.toNativeSeparators(directory))

    def clear_fields(self):
        """Clear selected paths, scan results, progress, and status text."""
        self.dir.clear()
        for chk in (self.chk_md5, self.chk_sha1, self.chk_sha256, self.chk_sha512):
            chk.setChecked(True)
        self.reset_scan_output()
        self.status_label.setText("Ready")

    def reset_scan_output(self):
        """Reset result table, progress bar, summary counts, and export buttons."""
        self.results_table.setRowCount(0)
        self.progress.setValue(0)
        self.pdfs_scanned.setText("0")
        self.hashes_found.setText("0")
        self.skipped_files.setText("0")
        self.scan_results = {}
        self.export_csv_btn.setEnabled(False)
        self.export_json_btn.setEnabled(False)

    def set_controls_enabled(self, enabled):
        """Enable or disable scan configuration controls during processing."""
        self.execute.setEnabled(enabled)
        self.clear.setEnabled(enabled)
        self.browse_pdf.setEnabled(enabled)
        self.dir.setEnabled(enabled)
        for chk in (self.chk_md5, self.chk_sha1, self.chk_sha256, self.chk_sha512):
            chk.setEnabled(enabled)

    def add_result(self, source, file_type, hash_type, hash_value):
        """Append one result row to the results table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        # The Source File column is stretched to fit the viewport, so long paths
        # are elided. Keep the full path available as a tooltip on hover.
        source_item = QTableWidgetItem(source)
        source_item.setToolTip(source)
        self.results_table.setItem(row, 0, source_item)
        self.results_table.setItem(row, 1, QTableWidgetItem(file_type))
        self.results_table.setItem(row, 2, QTableWidgetItem(hash_type))
        self.results_table.setItem(row, 3, QTableWidgetItem(hash_value))
        self.hashes_found.setText(str(row + 1))

    def search(self):
        """Validate user input and start the threaded hash scan."""
        directory = self.dir.text().strip()

        self.reset_scan_output()

        if not directory:
            QMessageBox.warning(self, "Input Error", "Select an input directory.")
            self.status_label.setText("Input directory is required")
            return

        hash_types = {
            name for name, chk in [
                ("MD5", self.chk_md5),
                ("SHA1", self.chk_sha1),
                ("SHA256", self.chk_sha256),
                ("SHA512", self.chk_sha512),
            ] if chk.isChecked()
        }
        if not hash_types:
            QMessageBox.warning(self, "Selection Error", "Select at least one hash type.")
            return
        self._last_hash_types = hash_types

        if not os.path.isdir(directory):
            QMessageBox.warning(self, "Input Error", "The input directory does not exist.")
            self.status_label.setText("Input directory does not exist")
            return

        self.status_label.setText("Scanning files...")
        self.set_controls_enabled(False)

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(directory, hash_types)
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.progress_updated.connect(self.progress.setValue)
        self.scan_worker.status_updated.connect(self.status_label.setText)
        self.scan_worker.result_found.connect(self.add_result)
        self.scan_worker.scan_finished.connect(self.scan_complete)
        self.scan_worker.scan_failed.connect(self.scan_failed)
        self.scan_worker.scan_finished.connect(self.scan_thread.quit)
        self.scan_worker.scan_failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread_finished)

        self.scan_thread.start()

    def scan_complete(self, results, skipped_count):
        """Update summary fields and enable export after a successful scan."""
        scanned_count = len(results) + skipped_count
        hash_count = sum(len(hashes) for hashes in results.values())

        self.scan_results = results
        self.pdfs_scanned.setText(str(scanned_count))
        self.hashes_found.setText(str(hash_count))
        self.skipped_files.setText(str(skipped_count))
        try:
            self.db.save_scan(
                directory=self.dir.text().strip(),
                scanned_at=datetime.now().isoformat(),
                hash_types=",".join(sorted(self._last_hash_types)),
                files_scanned=scanned_count,
                hashes_found=hash_count,
                skipped_files=skipped_count,
                results=results,
            )
            self.status_label.setText("Scan complete — saved to database.")
        except Exception as db_error:
            self.status_label.setText("Scan complete (database save failed: %s)" % db_error)
        self.set_controls_enabled(True)
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        QMessageBox.information(self, "Scan Complete", "Scan complete. Use Export CSV or Export JSON to save results.")

    def scan_failed(self, error):
        """Re-enable controls and report a scan failure."""
        self.status_label.setText("Scan failed")
        self.set_controls_enabled(True)
        QMessageBox.critical(self, "Scan Error", "The scan could not be completed: %s" % error)

    def scan_thread_finished(self):
        """Clear references after the scan thread finishes."""
        self.scan_thread = None
        self.scan_worker = None

    def closeEvent(self, event):
        """Stop any running scan thread before closing."""
        if self.scan_thread is not None and self.scan_thread.isRunning():
            self.scan_thread.quit()
            self.scan_thread.wait()
        event.accept()

    def open_scan_history(self):
        dialog = ScanHistoryDialog(self.db, self)
        dialog.results_load_requested.connect(self._load_historical_results)
        dialog.exec_()

    def _load_historical_results(self, scan, rows):
        self.reset_scan_output()
        scan_results = {}
        for row in rows:
            path = row['file_path']
            scan_results[path] = set()
            for hash_type in ('md5', 'sha1', 'sha256', 'sha512'):
                if row[hash_type] is not None:
                    scan_results[path].add((hash_type.upper(), row[hash_type]))
                    self.add_result(
                        row['file_path'], row['file_type'],
                        hash_type.upper(), row[hash_type]
                    )
        self.scan_results = scan_results
        self.pdfs_scanned.setText(str(scan["files_scanned"]))
        self.skipped_files.setText(str(scan["skipped_files"]))
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        self.status_label.setText(
            "Historical scan from %s loaded." % scan["scanned_at"][:10]
        )

    def export_csv(self):
        """Prompt for a file path and export results as CSV."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "hashOutput.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, mode='w', newline='') as f:
                writer = csv.writer(f, lineterminator='\n')
                writer.writerow(['Absolute_Path', 'Hash_Type', 'Hash_Value'])
                for file_path, hashes in sorted(self.scan_results.items()):
                    for hash_type, hash_value in sorted(hashes):
                        writer.writerow([file_path, hash_type, hash_value])
            self.status_label.setText("Exported CSV: %s" % path)
            QMessageBox.information(self, "Export Complete", "CSV saved to:\n%s" % path)
        except Exception as error:
            QMessageBox.critical(self, "Export Error", "Could not save CSV: %s" % error)

    def export_json(self):
        """Prompt for a file path and export results as JSON."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "hashOutput.json", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            rows = []
            for file_path, hashes in sorted(self.scan_results.items()):
                for hash_type, hash_value in sorted(hashes):
                    rows.append({"absolute_path": file_path, "hash_type": hash_type, "hash_value": hash_value})
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(rows, f, indent=2)
            self.status_label.setText("Exported JSON: %s" % path)
            QMessageBox.information(self, "Export Complete", "JSON saved to:\n%s" % path)
        except Exception as error:
            QMessageBox.critical(self, "Export Error", "Could not save JSON: %s" % error)


class ScanHistoryDialog(QDialog):
    results_load_requested = pyqtSignal(dict, list)

    TIME_RANGES = [
        ("Today",        0),
        ("Last 7 days",  7),
        ("Last 30 days", 30),
        ("Last 90 days", 90),
        ("All time",     None),
    ]

    def __init__(self, db, parent=None):
        QDialog.__init__(self, parent)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.db = db
        self._scan_rows = []

        self.setWindowTitle("Scan History")
        self.setGeometry(250, 250, 750, 400)

        layout = QVBoxLayout()
        filter_layout = QHBoxLayout()
        button_layout = QHBoxLayout()

        self.time_range_combo = QComboBox()
        for label, _ in self.TIME_RANGES:
            self.time_range_combo.addItem(label)
        self.time_range_combo.setCurrentIndex(2)  # Default: Last 30 days

        self.scans_table = QTableWidget(0, 4)
        self.scans_table.setHorizontalHeaderLabels(
            ["Date / Time", "Directory", "Files", "Hashes Found"]
        )
        self.scans_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.scans_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.scans_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.scans_table.setAlternatingRowColors(True)
        self.scans_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.scans_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self.scans_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )
        self.scans_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeToContents
        )

        self.load_btn = QPushButton("Load Selected")
        close_btn = QPushButton("Close")

        filter_layout.addWidget(QLabel("Show:"))
        filter_layout.addWidget(self.time_range_combo)
        filter_layout.addStretch()

        button_layout.addStretch()
        button_layout.addWidget(self.load_btn)
        button_layout.addWidget(close_btn)

        layout.addLayout(filter_layout)
        layout.addWidget(self.scans_table)
        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.time_range_combo.currentIndexChanged.connect(self._refresh)
        self.load_btn.clicked.connect(self._load_selected)
        close_btn.clicked.connect(self.close)

        self._refresh()

    def _since_for_index(self, index):
        _, days = self.TIME_RANGES[index]
        if days is None:
            return None
        if days == 0:
            return datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
        return (datetime.now() - timedelta(days=days)).isoformat()

    def _refresh(self):
        since = self._since_for_index(self.time_range_combo.currentIndex())
        self._scan_rows = self.db.get_scans(since=since)
        self.scans_table.setRowCount(0)
        for scan in self._scan_rows:
            row = self.scans_table.rowCount()
            self.scans_table.insertRow(row)
            self.scans_table.setItem(
                row, 0,
                QTableWidgetItem(scan["scanned_at"].replace("T", " ")[:16])
            )
            self.scans_table.setItem(row, 1, QTableWidgetItem(scan["directory"]))
            self.scans_table.setItem(
                row, 2, QTableWidgetItem(str(scan["files_scanned"]))
            )
            self.scans_table.setItem(
                row, 3, QTableWidgetItem(str(scan["hashes_found"]))
            )

    def _load_selected(self):
        row_index = self.scans_table.currentRow()
        if row_index < 0:
            return
        scan = self._scan_rows[row_index]
        rows = self.db.get_results(scan["id"])
        self.results_load_requested.emit(scan, rows)
        self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    p = pdfAnalysis()
    p.show()
    app.exec_()
