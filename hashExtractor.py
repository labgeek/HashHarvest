from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from extractor import HashExtractor
import os
import sys


def resource_path(filename):
    """Return a file path that works from source and PyInstaller bundles."""
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


class ScanWorker(QObject):
    """Run PDF extraction in a worker thread and emit GUI-safe signals."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    result_found = pyqtSignal(str, str, str, str)
    scan_finished = pyqtSignal(dict, int, str)
    scan_failed = pyqtSignal(str)

    def __init__(self, directory, save_path):
        """Create a worker for the selected input directory and output path."""
        QObject.__init__(self)
        self.directory = directory
        self.save_path = save_path

    def run(self):
        """Execute extraction and emit completion or failure signals."""
        try:
            extractor = HashExtractor(self.directory, self.save_path)
            results = extractor.extract(
                self.progress_updated.emit,
                self.status_updated.emit,
                self.result_found.emit,
            )
            self.scan_finished.emit(results, len(extractor.errors), self.save_path)
        except Exception as error:
            self.scan_failed.emit(str(error))


class ReadmeWindow(QDialog):
    """Display README.md in a separate read-only dialog."""

    closed = pyqtSignal()

    def __init__(self, readme_path, parent=None):
        """Create the README viewer for the provided README path."""
        QDialog.__init__(self, parent)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.readme_path = readme_path

        layout = QVBoxLayout()
        self.viewer = QTextEdit()
        close_button = QPushButton("Close")

        self.viewer.setReadOnly(True)
        self.viewer.setLineWrapMode(QTextEdit.NoWrap)

        layout.addWidget(self.viewer)
        layout.addWidget(close_button)

        self.setLayout(layout)
        self.setGeometry(260, 260, 800, 600)
        self.setWindowTitle("README.md")

        close_button.clicked.connect(self.close)
        self.load_readme()

    def load_readme(self):
        """Load README.md text into the viewer, or show the read error."""
        try:
            with open(self.readme_path, "r", encoding="utf-8") as readme:
                self.viewer.setPlainText(readme.read())
        except OSError as error:
            self.viewer.setPlainText("Could not open README.md: %s" % error)

    def closeEvent(self, event):
        """Emit a close signal so the main window can update its button text."""
        self.closed.emit()
        QDialog.closeEvent(self, event)


class pdfAnalysis(QDialog):
    """Main MD5Extractor application dialog."""

    def __init__(self):
        """Build the GUI, initialize state, and connect widget signals."""
        QDialog.__init__(self)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.scan_thread = None
        self.scan_worker = None
        self.readme_window = None

        main_layout = QVBoxLayout()
        content_layout = QHBoxLayout()
        controls_layout = QVBoxLayout()
        pdf_layout = QHBoxLayout()
        save_layout = QHBoxLayout()
        button_layout = QHBoxLayout()
        summary_layout = QGridLayout()
        header_layout = QVBoxLayout()

        config_group = QGroupBox("File Scan Configuration")
        config_layout = QVBoxLayout()
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        summary_group = QGroupBox("Scan Summary")

        self.dir = QLineEdit()
        self.save_location = QLineEdit()
        self.progress = QProgressBar()
        self.status_label = QLabel("Ready")
        self.title_label = QLabel("HashExtractor v0.3 by labgeek")
        self.date_label = QLabel(QDate.currentDate().toString("MMMM d, yyyy"))
        self.pdfs_scanned = QLabel("0")
        self.hashes_found = QLabel("0")
        self.skipped_files = QLabel("0")
        self.output_file = QLineEdit()
        self.results_table = QTableWidget(0, 4)

        self.execute = QPushButton("Start Scan")
        self.clear = QPushButton("Clear Form")
        self.readme_button = QPushButton("Open README")
        self.browse_pdf = QPushButton("Select Input Folder")
        self.browse_save = QPushButton("Select Output Folder")

        self.dir.setPlaceholderText("Select the directory containing files to scan")
        self.save_location.setPlaceholderText("Select the directory for hashOutput.txt")
        self.progress.setValue(0)
        self.progress.setAlignment(Qt.AlignCenter)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.date_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        self.output_file.setReadOnly(True)
        self.output_file.setPlaceholderText("Not generated")

        self.results_table.setHorizontalHeaderLabels(["Source File", "File Type", "Hash Type", "Hash Value"])
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        pdf_layout.addWidget(QLabel("Input Directory"))
        pdf_layout.addWidget(self.dir)
        pdf_layout.addWidget(self.browse_pdf)

        save_layout.addWidget(QLabel("Output Directory"))
        save_layout.addWidget(self.save_location)
        save_layout.addWidget(self.browse_save)

        button_layout.addWidget(self.execute)
        button_layout.addWidget(self.clear)
        button_layout.addWidget(self.readme_button)
        button_layout.addStretch()

        config_layout.addLayout(pdf_layout)
        config_layout.addLayout(save_layout)
        config_layout.addWidget(QLabel("Progress"))
        config_layout.addWidget(self.progress)
        config_layout.addLayout(button_layout)
        config_group.setLayout(config_layout)

        summary_layout.addWidget(QLabel("Files Scanned"), 0, 0)
        summary_layout.addWidget(self.pdfs_scanned, 0, 1)
        summary_layout.addWidget(QLabel("Hashes Found"), 1, 0)
        summary_layout.addWidget(self.hashes_found, 1, 1)
        summary_layout.addWidget(QLabel("Skipped Files"), 2, 0)
        summary_layout.addWidget(self.skipped_files, 2, 1)
        summary_layout.addWidget(QLabel("Output File"), 3, 0)
        summary_layout.addWidget(self.output_file, 3, 1)
        summary_layout.setColumnStretch(1, 1)
        summary_group.setLayout(summary_layout)

        controls_layout.addWidget(config_group)
        controls_layout.addWidget(summary_group)
        controls_layout.addStretch()

        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)

        content_layout.addLayout(controls_layout, 2)
        content_layout.addWidget(results_group, 3)

        header_layout.addWidget(self.title_label)
        header_layout.addWidget(self.date_label)
        main_layout.addLayout(header_layout)
        main_layout.addLayout(content_layout)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)
        self.setGeometry(200, 200, 1050, 420)
        self.setWindowTitle("HashExtractor v0.3 by labgeek")
        self.setFocus()

        self.execute.clicked.connect(self.search)
        self.clear.clicked.connect(self.clear_fields)
        self.readme_button.clicked.connect(self.toggle_readme)
        self.browse_pdf.clicked.connect(self.browse_pdf_directory)
        self.browse_save.clicked.connect(self.browse_file)

    def browse_pdf_directory(self):
        """Open a folder picker and populate the input PDF directory field."""
        directory = QFileDialog.getExistingDirectory(self, caption="Select Input Directory", directory=".")
        if directory:
            self.dir.setText(QDir.toNativeSeparators(directory))

    def browse_file(self):
        """Open a folder picker and populate the output directory field."""
        directory = QFileDialog.getExistingDirectory(self, caption="Select Output Directory", directory=".")
        if directory:
            self.save_location.setText(QDir.toNativeSeparators(directory))

    def clear_fields(self):
        """Clear selected paths, scan results, progress, and status text."""
        self.dir.clear()
        self.save_location.clear()
        self.reset_scan_output()
        self.status_label.setText("Ready")

    def toggle_readme(self):
        """Open README.md in a separate window, or close it if already open."""
        if self.readme_window is not None:
            self.readme_window.close()
            return

        readme_path = resource_path("README.md")
        self.readme_window = ReadmeWindow(readme_path, self)
        self.readme_window.closed.connect(self.readme_closed)
        self.readme_window.show()
        self.readme_button.setText("Close README")

    def readme_closed(self):
        """Reset README window state after the viewer is closed."""
        self.readme_window = None
        self.readme_button.setText("Open README")

    def reset_scan_output(self):
        """Reset result table, progress bar, summary counts, and output path."""
        self.results_table.setRowCount(0)
        self.progress.setValue(0)
        self.pdfs_scanned.setText("0")
        self.hashes_found.setText("0")
        self.skipped_files.setText("0")
        self.output_file.clear()
        self.output_file.setToolTip("")

    def set_controls_enabled(self, enabled):
        """Enable or disable scan configuration controls during processing."""
        self.execute.setEnabled(enabled)
        self.clear.setEnabled(enabled)
        self.browse_pdf.setEnabled(enabled)
        self.browse_save.setEnabled(enabled)
        self.dir.setEnabled(enabled)
        self.save_location.setEnabled(enabled)

    def add_result(self, source, file_type, hash_type, hash_value):
        """Append one result row to the results table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(source))
        self.results_table.setItem(row, 1, QTableWidgetItem(file_type))
        self.results_table.setItem(row, 2, QTableWidgetItem(hash_type))
        self.results_table.setItem(row, 3, QTableWidgetItem(hash_value))
        self.hashes_found.setText(str(row + 1))

    def search(self):
        """Validate user input and start the threaded PDF scan."""
        directory = self.dir.text().strip()
        output_directory = self.save_location.text().strip()

        self.reset_scan_output()

        if not directory:
            QMessageBox.warning(self, "Input Error", "Select an input directory.")
            self.status_label.setText("Input directory is required")
            return

        if not output_directory:
            QMessageBox.warning(self, "Output Error", "Select an output directory.")
            self.status_label.setText("Output directory is required")
            return

        save_location = os.path.join(output_directory, "hashOutput.txt")
        extractor = HashExtractor(directory, save_location)

        if extractor.dir_exists() == False:
            QMessageBox.warning(self, "Input Error", "The input directory does not exist.")
            self.status_label.setText("Input directory does not exist")
            return

        try:
            os.makedirs(output_directory, exist_ok=True)
        except OSError as error:
            QMessageBox.warning(self, "Output Error", "The output directory could not be created: %s" % error)
            self.status_label.setText("Output directory could not be created")
            return

        self.status_label.setText("Scanning files...")
        self.set_controls_enabled(False)

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(directory, save_location)
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

    def scan_complete(self, results, skipped_count, save_path):
        """Update summary fields and notify the user after a successful scan."""
        scanned_count = len(results) + skipped_count
        hash_count = sum(len(md5s) for md5s in results.values())

        self.pdfs_scanned.setText(str(scanned_count))
        self.hashes_found.setText(str(hash_count))
        self.skipped_files.setText(str(skipped_count))
        self.output_file.setText(save_path)
        self.output_file.setToolTip(save_path)
        self.status_label.setText("Scan complete")
        self.set_controls_enabled(True)
        QMessageBox.information(self, "Scan Complete", "Parsing complete. Output saved to %s" % save_path)

    def scan_failed(self, error):
        """Re-enable controls and report a scan failure."""
        self.status_label.setText("Scan failed")
        self.set_controls_enabled(True)
        QMessageBox.critical(self, "Scan Error", "The scan could not be completed: %s" % error)

    def scan_thread_finished(self):
        """Clear references after the scan thread finishes."""
        self.scan_thread = None
        self.scan_worker = None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    p = pdfAnalysis()
    p.show()
    app.exec_()
