"""PyQt5 desktop application for extracting cryptographic hashes from files."""

import csv
import json
import os
import re
import sys
from datetime import datetime, timedelta
from hashharvest.persistence.db import HashDatabase

from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from hashharvest.extractor import HashHarvest


class ScanWorker(QObject):
    """Run hash extraction in a worker thread and emit GUI-safe signals."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    result_found = pyqtSignal(str, str, str, str, int, str)
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
            extractor = HashHarvest(self.directory)
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
    """Main HashHarvest application dialog."""

    def __init__(self):
        """Build the GUI, initialize state, and connect widget signals."""
        QDialog.__init__(self)
        self.setWindowFlags(
            self.windowFlags()
            & ~Qt.WindowContextHelpButtonHint
            | Qt.WindowMaximizeButtonHint
            | Qt.WindowMinimizeButtonHint
        )

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
        self.title_label = QLabel("HashHarvest")
        self.subtitle_label = QLabel("Multi-Algorithm File Hash Analysis")
        self.version_label = QLabel("v0.7.0")
        self.date_label = QLabel(QDate.currentDate().toString("MMMM d, yyyy"))
        self.pdfs_scanned = QLabel("0")
        self.hashes_found = QLabel("0")
        self.skipped_files = QLabel("0")
        self.results_table = QTableWidget(0, 6)
        self.search_box = QLineEdit()
        self.show_context_chk = QCheckBox("Show Context")

        self.execute = QPushButton("Start Scan")
        self.clear = QPushButton("Clear Form")
        self.browse_pdf = QPushButton("Select Input Folder")
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_json_btn = QPushButton("Export JSON")
        self.scan_history_btn = QPushButton("Scan History")
        self.watchlist_btn = QPushButton("Watchlist")

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

        self.results_table.setHorizontalHeaderLabels(
            ["Source File", "File Type", "Hash Type", "Hash Value", "Line", "Context"]
        )
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        # Paths are long; elide the middle so the drive and filename stay visible.
        self.results_table.setTextElideMode(Qt.ElideMiddle)
        header = self.results_table.horizontalHeader()
        for col in range(self.results_table.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.Interactive)
        # Hash Value stretches by default; Context stretches when the columns are shown.
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_table.setColumnWidth(0, 420)
        self.results_table.setColumnWidth(1, 90)
        self.results_table.setColumnWidth(2, 90)
        self.results_table.setColumnWidth(4, 60)
        self.results_table.setColumnWidth(5, 400)
        self.results_table.setColumnHidden(4, True)
        self.results_table.setColumnHidden(5, True)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.search_box.setPlaceholderText("Filter results…")
        self.search_box.setClearButtonEnabled(True)

        pdf_layout.addWidget(QLabel("Input Directory"))
        pdf_layout.addWidget(self.dir)
        pdf_layout.addWidget(self.browse_pdf)

        button_layout.addWidget(self.execute)
        button_layout.addWidget(self.clear)
        button_layout.addWidget(self.scan_history_btn)
        button_layout.addWidget(self.watchlist_btn)
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

        results_filter_layout = QHBoxLayout()
        results_filter_layout.addWidget(self.search_box)
        results_filter_layout.addWidget(self.show_context_chk)
        results_layout.addLayout(results_filter_layout)
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
        self.setWindowTitle("HashHarvest v0.7.0 (labgeek)")
        self.setFocus()

        self.execute.clicked.connect(self.search)
        self.clear.clicked.connect(self.clear_fields)
        self.browse_pdf.clicked.connect(self.browse_pdf_directory)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.export_json_btn.clicked.connect(self.export_json)
        self.scan_history_btn.clicked.connect(self.open_scan_history)
        self.search_box.textChanged.connect(self._filter_results)
        self.results_table.customContextMenuRequested.connect(self._show_results_context_menu)
        self.show_context_chk.toggled.connect(self._toggle_context_columns)
        self.watchlist_btn.clicked.connect(self.open_watchlist_manager)

        if getattr(sys, 'frozen', False):
            _db_path = os.path.join(os.path.dirname(sys.executable), "hashharvest.db")
        else:
            # Go up one level from hashharvest/ to the project root
            _db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "hashharvest.db"
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
        self.results_table.setSortingEnabled(False)
        self.results_table.setRowCount(0)
        self.search_box.clear()
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

    def add_result(self, source, file_type, hash_type, hash_value, line_no, context):
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
        line_item = QTableWidgetItem(str(line_no) if line_no else "")
        line_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.results_table.setItem(row, 4, line_item)
        self.results_table.setItem(row, 5, QTableWidgetItem(context or ""))
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
            scan_id = self.db.save_scan(
                directory=self.dir.text().strip(),
                scanned_at=datetime.now().isoformat(),
                hash_types=",".join(sorted(self._last_hash_types)),
                files_scanned=scanned_count,
                hashes_found=hash_count,
                skipped_files=skipped_count,
                results=results,
            )
            self.status_label.setText("Scan complete — saved to database.")
            self._apply_watchlist_highlights(scan_id)
        except Exception as db_error:
            self.status_label.setText("Scan complete (database save failed: %s)" % db_error)
        self.results_table.setSortingEnabled(True)
        self.set_controls_enabled(True)
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        QMessageBox.information(self, "Scan Complete", "Scan complete. Use Export CSV or Export JSON to save results.")

    def scan_failed(self, error):
        """Re-enable controls and report a scan failure."""
        self.status_label.setText("Scan failed")
        self.results_table.setSortingEnabled(True)
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
        """Open the Scan History dialog and connect its load signal."""
        dialog = ScanHistoryDialog(self.db, self)
        dialog.results_load_requested.connect(self._load_historical_results)
        dialog.exec_()

    def _load_historical_results(self, scan, rows):
        """Populate the UI with results loaded from a historical scan record.

        Args:
            scan: A dict of scan metadata (directory, scanned_at, files_scanned, etc.).
            rows: A list of result dicts, each with file_path, file_type, hash_type,
                and hash_value keys.
        """
        self.reset_scan_output()
        scan_results = {}
        for row in rows:
            path = row['file_path']
            if path not in scan_results:
                scan_results[path] = set()
            line_no = row['line_number'] or 0
            context = row['context'] or ""
            scan_results[path].add((row['hash_type'], row['hash_value'], line_no, context))
            self.add_result(
                row['file_path'], row['file_type'],
                row['hash_type'], row['hash_value'], line_no, context
            )
        self.scan_results = scan_results
        self.pdfs_scanned.setText(str(scan["files_scanned"]))
        self.skipped_files.setText(str(scan["skipped_files"]))
        self.results_table.setSortingEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        self.status_label.setText(
            "Historical scan from %s loaded." % scan["scanned_at"][:10]
        )
        self._apply_watchlist_highlights(scan["id"])

    def open_watchlist_manager(self):
        """Open the Watchlist Manager dialog."""
        dialog = WatchlistDialog(self.db, self)
        dialog.exec_()

    def _apply_watchlist_highlights(self, scan_id):
        """Highlight rows red where the hash value matches any watchlist entry."""
        try:
            matches = self.db.get_scan_matches(scan_id)
        except Exception:
            return
        if not matches:
            return
        red = QColor(220, 80, 80)
        hit_count = 0
        for row in range(self.results_table.rowCount()):
            item = self.results_table.item(row, 3)
            if item and item.text() in matches:
                hit_count += 1
                for col in range(self.results_table.columnCount()):
                    cell = self.results_table.item(row, col)
                    if cell:
                        cell.setForeground(QColor(255, 255, 255))
                        cell.setBackground(red)
        if hit_count:
            self.status_label.setText(
                self.status_label.text() +
                " — ⚠ %d watchlist hit%s" % (hit_count, "s" if hit_count != 1 else "")
            )

    def _toggle_context_columns(self, checked):
        """Show/hide Line and Context columns; swap which column gets stretch space."""
        header = self.results_table.horizontalHeader()
        for col in (4, 5):
            self.results_table.setColumnHidden(col, not checked)
        if checked:
            header.setSectionResizeMode(3, QHeaderView.Interactive)
            header.setSectionResizeMode(5, QHeaderView.Stretch)
        else:
            header.setSectionResizeMode(3, QHeaderView.Stretch)
            header.setSectionResizeMode(5, QHeaderView.Interactive)

    def _filter_results(self, text):
        """Show only rows where any cell contains text (case-insensitive); show all when empty."""
        needle = text.lower()
        for row in range(self.results_table.rowCount()):
            match = not needle or any(
                needle in (self.results_table.item(row, col).text().lower()
                           if self.results_table.item(row, col) else "")
                for col in range(self.results_table.columnCount())
            )
            self.results_table.setRowHidden(row, not match)

    def _show_results_context_menu(self, pos):
        """Right-click context menu: copy the hash value or the full row."""
        row = self.results_table.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        copy_hash_action = menu.addAction("Copy Hash")
        copy_row_action = menu.addAction("Copy Row")
        action = menu.exec_(self.results_table.viewport().mapToGlobal(pos))
        if action == copy_hash_action:
            item = self.results_table.item(row, 3)
            if item:
                QApplication.clipboard().setText(item.text())
        elif action == copy_row_action:
            parts = [
                self.results_table.item(row, col).text()
                if self.results_table.item(row, col) else ""
                for col in range(self.results_table.columnCount())
            ]
            QApplication.clipboard().setText("\t".join(parts))

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
                writer.writerow(['Absolute_Path', 'Hash_Type', 'Hash_Value', 'Line', 'Context'])
                for file_path, hashes in sorted(self.scan_results.items()):
                    for hash_type, hash_value, line_no, context in sorted(hashes):
                        writer.writerow([file_path, hash_type, hash_value, line_no, context])
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
                for hash_type, hash_value, line_no, context in sorted(hashes):
                    rows.append({
                        "absolute_path": file_path,
                        "hash_type": hash_type,
                        "hash_value": hash_value,
                        "line": line_no,
                        "context": context,
                    })
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(rows, f, indent=2)
            self.status_label.setText("Exported JSON: %s" % path)
            QMessageBox.information(self, "Export Complete", "JSON saved to:\n%s" % path)
        except Exception as error:
            QMessageBox.critical(self, "Export Error", "Could not save JSON: %s" % error)


class ScanHistoryDialog(QDialog):
    """Dialog that lists past scans and allows loading a previous result set into the main window.

    Emits ``results_load_requested(scan_dict, rows_list)`` when the user chooses to
    reload a historical scan.
    """

    results_load_requested = pyqtSignal(dict, list)

    TIME_RANGES = [
        ("Today",        0),
        ("Last 7 days",  7),
        ("Last 30 days", 30),
        ("Last 90 days", 90),
        ("All time",     None),
    ]

    def __init__(self, db, parent=None):
        """Build the history dialog, load the default time range, and wire up signals.

        Args:
            db: A ``HashDatabase`` instance used to query past scans and their results.
            parent: Optional parent widget.
        """
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
        """Return an ISO-8601 timestamp lower bound for the selected time-range combo index.

        Args:
            index: Index into ``TIME_RANGES``.

        Returns:
            An ISO-8601 string (e.g. ``"2026-05-21T00:00:00"``) representing the earliest
            scan time to include, or ``None`` when the range is "All time".
        """
        _, days = self.TIME_RANGES[index]
        if days is None:
            return None
        if days == 0:
            return datetime.now().replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
        return (datetime.now() - timedelta(days=days)).isoformat()

    def _refresh(self):
        """Reload the scans table from the database for the currently selected time range."""
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
        """Emit ``results_load_requested`` for the highlighted scan row and close the dialog."""
        row_index = self.scans_table.currentRow()
        if row_index < 0:
            return
        scan = self._scan_rows[row_index]
        rows = self.db.get_results(scan["id"])
        self.results_load_requested.emit(scan, rows)
        self.close()


class WatchlistDialog(QDialog):
    """Create and manage named watchlists of known-bad hashes.

    Hashes can be pasted directly or imported from a TXT/CSV file.
    Any valid MD5 / SHA1 / SHA256 / SHA512 hex string found in the input
    is extracted automatically, so structured formats (CSV with labels,
    threat-intel reports) work without pre-processing.
    """

    # Extracts any standalone 32/40/64/128 hex string — same logic as the extractor.
    _HASH_RE = re.compile(
        r'(?<![a-fA-F0-9])'
        r'([a-fA-F0-9]{128}|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})'
        r'(?![a-fA-F0-9])',
        re.IGNORECASE,
    )

    def __init__(self, db, parent=None):
        """Build the dialog, load existing watchlists, and wire up signals.

        Args:
            db: A ``HashDatabase`` instance.
            parent: Optional parent widget.
        """
        QDialog.__init__(self, parent)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.db = db
        self._watchlist_rows = []

        self.setWindowTitle("Watchlist Manager")
        self.setGeometry(270, 270, 680, 460)

        layout = QVBoxLayout()

        # Watchlist list + New / Delete buttons
        list_group = QGroupBox("Watchlists")
        list_layout = QHBoxLayout()
        self.watchlist_list = QListWidget()
        self.watchlist_list.setMaximumHeight(140)
        list_btn_layout = QVBoxLayout()
        self.new_btn = QPushButton("New…")
        self.delete_btn = QPushButton("Delete Selected")
        list_btn_layout.addWidget(self.new_btn)
        list_btn_layout.addWidget(self.delete_btn)
        list_btn_layout.addStretch()
        list_layout.addWidget(self.watchlist_list, 3)
        list_layout.addLayout(list_btn_layout, 1)
        list_group.setLayout(list_layout)

        # Import section
        import_group = QGroupBox("Import hashes into selected watchlist")
        import_layout = QVBoxLayout()
        self.paste_area = QPlainTextEdit()
        self.paste_area.setPlaceholderText(
            "Paste hashes here — one per line, CSV, or any free text.\n"
            "MD5 / SHA1 / SHA256 / SHA512 values are extracted automatically."
        )
        self.paste_area.setMaximumHeight(120)
        import_btn_row = QHBoxLayout()
        self.browse_btn = QPushButton("Browse File…")
        self.import_btn = QPushButton("Import from Text")
        self.import_status = QLabel("")
        import_btn_row.addWidget(self.browse_btn)
        import_btn_row.addWidget(self.import_btn)
        import_btn_row.addWidget(self.import_status, 1)
        import_layout.addWidget(self.paste_area)
        import_layout.addLayout(import_btn_row)
        import_group.setLayout(import_layout)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = QPushButton("Close")
        close_row.addWidget(close_btn)

        layout.addWidget(list_group)
        layout.addWidget(import_group)
        layout.addLayout(close_row)
        self.setLayout(layout)

        self.new_btn.clicked.connect(self._new_watchlist)
        self.delete_btn.clicked.connect(self._delete_watchlist)
        self.browse_btn.clicked.connect(self._browse_file)
        self.import_btn.clicked.connect(self._import_from_text)
        close_btn.clicked.connect(self.close)

        self._refresh()

    def _refresh(self):
        """Reload the watchlist display from the database."""
        self._watchlist_rows = self.db.get_watchlists()
        self.watchlist_list.clear()
        for w in self._watchlist_rows:
            count = w['entry_count']
            self.watchlist_list.addItem(
                "%s  (%d hash%s)" % (w['name'], count, "es" if count != 1 else "")
            )

    def _new_watchlist(self):
        """Prompt for a name and create a new watchlist."""
        name, ok = QInputDialog.getText(self, "New Watchlist", "Watchlist name:")
        if ok and name.strip():
            self.db.create_watchlist(name.strip())
            self._refresh()

    def _delete_watchlist(self):
        """Delete the selected watchlist after confirmation."""
        idx = self.watchlist_list.currentRow()
        if idx < 0:
            return
        w = self._watchlist_rows[idx]
        reply = QMessageBox.question(
            self, "Delete Watchlist",
            "Delete \"%s\" and all %d of its entries?" % (w['name'], w['entry_count']),
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.db.delete_watchlist(w['id'])
            self._refresh()

    def _browse_file(self):
        """Read a file and import any hashes found in it into the selected watchlist."""
        idx = self.watchlist_list.currentRow()
        if idx < 0:
            self.import_status.setText("Select a watchlist first.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Hashes From File", "",
            "Text / CSV files (*.txt *.csv *.log *.json);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                text = fh.read()
        except Exception as err:
            self.import_status.setText("Could not read file: %s" % err)
            return
        self._do_import(self._watchlist_rows[idx]['id'], text, source=os.path.basename(path))

    def _import_from_text(self):
        """Import hashes from the paste area into the selected watchlist."""
        idx = self.watchlist_list.currentRow()
        if idx < 0:
            self.import_status.setText("Select a watchlist first.")
            return
        text = self.paste_area.toPlainText()
        if not text.strip():
            self.import_status.setText("Nothing to import.")
            return
        self._do_import(self._watchlist_rows[idx]['id'], text, source="paste")
        self.paste_area.clear()

    def _do_import(self, watchlist_id, text, source):
        """Extract hashes from text, add to watchlist, update status label."""
        hashes = self._extract_hashes(text)
        if not hashes:
            self.import_status.setText("No valid hashes found in %s." % source)
            return
        added = self.db.import_hashes(watchlist_id, hashes)
        self.import_status.setText(
            "Added %d new hash%s from %s (%d already present)."
            % (added, "es" if added != 1 else "", source, len(hashes) - added)
        )
        self._refresh()

    @classmethod
    def _extract_hashes(cls, text):
        """Return a set of lowercase hex hash strings found anywhere in text."""
        return {m.group(1).lower() for m in cls._HASH_RE.finditer(text)}


if __name__ == "__main__":
    app = QApplication(sys.argv)
    p = pdfAnalysis()
    p.show()
    app.exec_()
