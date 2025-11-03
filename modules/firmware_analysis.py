from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFileDialog, QTextEdit, QGroupBox,
                             QFormLayout, QLineEdit, QProgressBar, QComboBox)
from PySide6.QtCore import Qt, QTimer
import os
import hashlib
import json
from datetime import datetime

class FirmwareAnalysisGUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.firmware_path = ""
        self.analysis_results = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setSpacing(15)
        
        # Header
        header = QLabel("Firmware & OS Analysis")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #89b4fa;
            margin-bottom: 15px;
        """)
        main_layout.addWidget(header)
        
        # File Selection Group
        file_group = QGroupBox("Firmware File")
        file_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #313244;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        
        file_layout = QHBoxLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_path.setPlaceholderText("Select a firmware file to analyze...")
        self.file_path.setStyleSheet("""
            QLineEdit {
                background-color: #181825;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 8px;
                color: #cdd6f4;
            }
        """)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #89b4fa;
                color: #1e1e2e;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #74c7ec;
            }
        """)
        browse_btn.clicked.connect(self.browse_firmware)
        
        file_layout.addWidget(self.file_path, 1)
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)
        
        # Analysis Options Group
        options_group = QGroupBox("Analysis Options")
        options_group.setStyleSheet(file_group.styleSheet())
        
        options_layout = QFormLayout()
        options_layout.setHorizontalSpacing(20)
        options_layout.setVerticalSpacing(10)
        
        # Analysis type selection
        self.analysis_type = QComboBox()
        self.analysis_type.addItems(["Quick Scan", "Full Analysis", "Custom"])
        self.analysis_type.setStyleSheet("""
            QComboBox {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        
        # Checkboxes for analysis options
        self.chk_extract = self.create_checkbox("Extract Files")
        self.chk_hashes = self.create_checkbox("Calculate Hashes")
        self.chk_strings = self.create_checkbox("Extract Strings")
        self.chk_entropy = self.create_checkbox("Entropy Analysis")
        
        options_layout.addRow("Analysis Type:", self.analysis_type)
        options_layout.addRow(self.chk_extract)
        options_layout.addRow(self.chk_hashes)
        options_layout.addRow(self.chk_strings)
        options_layout.addRow(self.chk_entropy)
        
        options_group.setLayout(options_layout)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(True)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #313244;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                width: 20px;
            }
        """)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("🔍 Analyze Firmware")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #a6e3a1;
                color: #1e1e2e;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        """)
        self.analyze_btn.clicked.connect(self.analyze_firmware)
        self.analyze_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f38ba8;
                color: #1e1e2e;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_analysis)
        
        btn_layout.addStretch()
        btn_layout.addWidget(self.analyze_btn)
        btn_layout.addWidget(self.clear_btn)
        
        # Results Area
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setStyleSheet("""
            QTextEdit {
                background-color: #181825;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 10px;
                color: #cdd6f4;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_area.setPlaceholderText("Analysis results will appear here...")
        
        # Add widgets to main layout
        main_layout.addWidget(file_group)
        main_layout.addWidget(options_group)
        main_layout.addWidget(self.progress)
        main_layout.addLayout(btn_layout)
        main_layout.addWidget(QLabel("<b>Analysis Results:</b>"))
        main_layout.addWidget(self.results_area, 1)
        
        # Set initial state
        self.update_ui_state()
    
    def create_checkbox(self, text):
        """Helper to create styled checkboxes"""
        checkbox = QPushButton(text)
        checkbox.setCheckable(True)
        checkbox.setChecked(True)
        checkbox.setStyleSheet("""
            QPushButton {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 5px 10px;
                text-align: left;
            }
            QPushButton:checked {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
            QPushButton:hover {
                background-color: #313244;
            }
        """)
        return checkbox
    
    def browse_firmware(self):
        """Open file dialog to select firmware file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Firmware File",
            "",
            "Firmware Files (*.bin *.img *.rom *.fw);;All Files (*)"
        )
        
        if file_path:
            self.firmware_path = file_path
            self.file_path.setText(file_path)
            self.analyze_btn.setEnabled(True)
            self.update_ui_state()
    
    def update_ui_state(self):
        """Update UI elements based on current state"""
        has_file = bool(self.firmware_path)
        self.analyze_btn.setEnabled(has_file)
        
        # Update options based on analysis type
        analysis_type = self.analysis_type.currentText()
        if analysis_type == "Quick Scan":
            self.chk_extract.setChecked(True)
            self.chk_hashes.setChecked(True)
            self.chk_strings.setChecked(False)
            self.chk_entropy.setChecked(False)
            self.chk_extract.setEnabled(False)
            self.chk_hashes.setEnabled(False)
            self.chk_strings.setEnabled(False)
            self.chk_entropy.setEnabled(False)
        elif analysis_type == "Full Analysis":
            self.chk_extract.setChecked(True)
            self.chk_hashes.setChecked(True)
            self.chk_strings.setChecked(True)
            self.chk_entropy.setChecked(True)
            self.chk_extract.setEnabled(False)
            self.chk_hashes.setEnabled(False)
            self.chk_strings.setEnabled(False)
            self.chk_entropy.setEnabled(False)
        else:  # Custom
            self.chk_extract.setEnabled(True)
            self.chk_hashes.setEnabled(True)
            self.chk_strings.setEnabled(True)
            self.chk_entropy.setEnabled(True)
    
    def analyze_firmware(self):
        """Start firmware analysis"""
        if not self.firmware_path or not os.path.isfile(self.firmware_path):
            self.show_error("Invalid firmware file")
            return
        
        # Reset UI
        self.analysis_results = {}
        self.results_area.clear()
        self.progress.setValue(0)
        
        # Get analysis options
        options = {
            'extract': self.chk_extract.isChecked(),
            'hashes': self.chk_hashes.isChecked(),
            'strings': self.chk_strings.isChecked(),
            'entropy': self.chk_entropy.isChecked(),
            'started_at': datetime.now().isoformat()
        }
        
        # Disable UI during analysis
        self.set_ui_enabled(False)
        
        # Simulate analysis progress
        self.simulate_analysis(options)
    
    def simulate_analysis(self, options):
        """Simulate firmware analysis with progress updates"""
        self.progress.setValue(10)
        QTimer.singleShot(500, lambda: self.update_analysis_progress(20, "Reading firmware file..."))
        QTimer.singleShot(1000, lambda: self.update_analysis_progress(30, "Calculating hashes..."))
        QTimer.singleShot(1500, lambda: self.update_analysis_progress(50, "Extracting files..."))
        QTimer.singleShot(2000, lambda: self.update_analysis_progress(70, "Analyzing file structure..."))
        QTimer.singleShot(2500, lambda: self.update_analysis_progress(90, "Generating report..."))
        QTimer.singleShot(3000, lambda: self.complete_analysis(options))
    
    def update_analysis_progress(self, value, message):
        """Update progress bar and status"""
        self.progress.setValue(value)
        self.append_result(f"[+] {message}")
    
    def complete_analysis(self, options):
        """Complete the analysis and show results"""
        self.progress.setValue(100)
        
        # Generate fake analysis results
        file_info = os.stat(self.firmware_path)
        self.analysis_results = {
            'file_info': {
                'filename': os.path.basename(self.firmware_path),
                'size': file_info.st_size,
                'modified': datetime.fromtimestamp(file_info.st_mtime).isoformat(),
                'md5': self.calculate_hash('md5'),
                'sha1': self.calculate_hash('sha1'),
                'sha256': self.calculate_hash('sha256')
            },
            'analysis': {
                'options': options,
                'completed_at': datetime.now().isoformat(),
                'findings': [
                    {
                        'severity': 'Info',
                        'description': 'Firmware file successfully analyzed',
                        'details': 'Basic analysis completed without errors.'
                    },
                    {
                        'severity': 'Medium',
                        'description': 'Potential hardcoded credentials found',
                        'details': 'Common default credentials detected in configuration files.'
                    },
                    {
                        'severity': 'High',
                        'description': 'Insecure cryptographic implementation',
                        'details': 'Weak hashing algorithm (MD5) detected in authentication module.'
                    }
                ]
            }
        }
        
        # Display results
        self.display_results()
        
        # Re-enable UI
        self.set_ui_enabled(True)
    
    def calculate_hash(self, algorithm):
        """Calculate file hash using specified algorithm"""
        try:
            hasher = hashlib.new(algorithm)
            with open(self.firmware_path, 'rb') as f:
                # Just read a small part for demonstration
                buf = f.read(4096)
                hasher.update(buf)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error calculating {algorithm}: {str(e)}"
    
    def display_results(self):
        """Display analysis results in the results area"""
        if not self.analysis_results:
            return
        
        # Display basic file info
        self.append_result("=== Firmware Analysis Report ===\n", "h2")
        
        file_info = self.analysis_results.get('file_info', {})
        self.append_result("File Information:", "h3")
        self.append_result(f"Filename: {file_info.get('filename', 'N/A')}")
        self.append_result(f"Size: {file_info.get('size', 0):,} bytes")
        self.append_result(f"Modified: {file_info.get('modified', 'N/A')}")
        self.append_result(f"MD5: {file_info.get('md5', 'N/A')}")
        self.append_result(f"SHA1: {file_info.get('sha1', 'N/A')}")
        self.append_result(f"SHA256: {file_info.get('sha256', 'N/A')}\n")
        
        # Display findings
        analysis = self.analysis_results.get('analysis', {})
        self.append_result("Analysis Findings:", "h3")
        
        findings = analysis.get('findings', [])
        if not findings:
            self.append_result("No issues found.")
        else:
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'Info')
                color = {
                    'High': '#f38ba8',
                    'Medium': '#f9e2af',
                    'Low': '#a6e3a1',
                    'Info': '#89b4fa'
                }.get(severity, '#cdd6f4')
                
                self.append_result(
                    f"{i}. [{severity}] {finding.get('description', 'N/A')}",
                    "finding",
                    color
                )
                self.append_result(f"   {finding.get('details', '')}\n")
        
        # Add analysis metadata
        self.append_result("\nAnalysis completed at: " + analysis.get('completed_at', 'N/A'))
    
    def append_result(self, text, style=None, color=None):
        """Append text to results area with optional styling"""
        if style == "h2":
            self.results_area.append(f"<h2 style='color: #89b4fa;'>{text}</h2>")
        elif style == "h3":
            self.results_area.append(f"<h3 style='color: #89b4fa;'>{text}</h3>")
        elif style == "finding" and color:
            self.results_area.append(f"<span style='color: {color}; font-weight: bold;'>{text}</span>")
        else:
            self.results_area.append(text)
        
        # Auto-scroll to bottom
        scrollbar = self.results_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def clear_analysis(self):
        """Clear analysis results and reset UI"""
        self.firmware_path = ""
        self.file_path.clear()
        self.results_area.clear()
        self.progress.setValue(0)
        self.analysis_results = {}
        self.analyze_btn.setEnabled(False)
        self.update_ui_state()
    
    def set_ui_enabled(self, enabled):
        """Enable or disable UI elements"""
        self.analyze_btn.setEnabled(enabled and bool(self.firmware_path))
        self.clear_btn.setEnabled(enabled)
        self.analysis_type.setEnabled(enabled)
        
        if enabled:
            self.update_ui_state()
        else:
            self.chk_extract.setEnabled(False)
            self.chk_hashes.setEnabled(False)
            self.chk_strings.setEnabled(False)
            self.chk_entropy.setEnabled(False)
    
    def show_error(self, message):
        """Display an error message"""
        self.append_result(f"[!] ERROR: {message}", "error")

if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = FirmwareAnalysisGUI()
    window.setWindowTitle("Firmware & OS Analysis")
    window.resize(1000, 800)
    window.show()
    sys.exit(app.exec())
