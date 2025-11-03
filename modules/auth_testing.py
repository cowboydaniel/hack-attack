"""
Authentication & Password Testing Module

This module provides tools for testing authentication mechanisms and password security.
It includes features for password strength analysis, common password checking,
and authentication protocol testing.
"""
import os
import hashlib
import json
import re
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QPushButton, QTextEdit, QComboBox, QProgressBar, QFileDialog,
                            QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
                            QFormLayout, QGroupBox, QCheckBox, QSpinBox, QSplitter)
from PySide6.QtCore import Qt, QThread, Signal, QTimer

class PasswordTester(QWidget):
    """Main widget for password testing functionality"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.common_passwords = self._load_common_passwords()
        self.setup_ui()
    
    def _load_common_passwords(self) -> set:
        """Load common passwords from file if available, otherwise return default set"""
        try:
            common_path = Path(__file__).parent.parent / 'data' / 'common_passwords.txt'
            if common_path.exists():
                with open(common_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return {line.strip() for line in f if line.strip()}
        except Exception as e:
            print(f"Warning: Could not load common passwords: {e}")
        
        # Return a small default set if file loading fails
        return {
            'password', '123456', '123456789', '12345', 'qwerty',
            'letmein', 'welcome', 'admin', 'password1', '12345678'
        }
    
    def setup_ui(self):
        """Set up the user interface"""
        main_layout = QVBoxLayout()
        
        # Create tabs for different testing methods
        self.tabs = QTabWidget()
        
        # Single Password Test Tab
        self.single_test_tab = QWidget()
        self.setup_single_test_ui()
        self.tabs.addTab(self.single_test_tab, "Single Password Test")
        
        # Password List Test Tab
        self.list_test_tab = QWidget()
        self.setup_list_test_ui()
        self.tabs.addTab(self.list_test_tab, "Password List Test")
        
        # Common Passwords Check Tab
        self.common_pw_tab = QWidget()
        self.setup_common_pw_ui()
        self.tabs.addTab(self.common_pw_tab, "Common Passwords")
        
        # Password Policy Check Tab
        self.policy_tab = QWidget()
        self.setup_policy_ui()
        self.tabs.addTab(self.policy_tab, "Password Policy")
        
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)
    
    def setup_single_test_ui(self):
        """Set up UI for single password testing"""
        layout = QVBoxLayout()
        
        # Password input
        form_layout = QFormLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password to test")
        form_layout.addRow("Password:", self.password_input)
        
        # Test button
        test_btn = QPushButton("Test Password")
        test_btn.clicked.connect(self.test_single_password)
        
        # Results area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        layout.addLayout(form_layout)
        layout.addWidget(test_btn)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results_text)
        
        self.single_test_tab.setLayout(layout)
    
    def setup_list_test_ui(self):
        """Set up UI for testing a list of passwords"""
        layout = QVBoxLayout()
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_password_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_btn)
        
        # Test options
        options_group = QGroupBox("Test Options")
        options_layout = QHBoxLayout()
        
        self.check_common = QCheckBox("Check against common passwords")
        self.check_common.setChecked(True)
        self.check_policy = QCheckBox("Check against password policy")
        self.check_policy.setChecked(True)
        
        options_layout.addWidget(self.check_common)
        options_layout.addWidget(self.check_policy)
        options_group.setLayout(options_layout)
        
        # Test button
        test_btn = QPushButton("Test Passwords")
        test_btn.clicked.connect(self.test_password_list)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Password", "Strength", "Issues"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(QLabel("Password File:"))
        layout.addLayout(file_layout)
        layout.addWidget(options_group)
        layout.addWidget(test_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results_table)
        
        self.list_test_tab.setLayout(layout)
    
    def setup_common_pw_ui(self):
        """Set up UI for checking against common passwords"""
        layout = QVBoxLayout()
        
        # Info label
        info_label = QLabel(
            "This tool checks if a password is in the list of most commonly used passwords.\n"
            "Common passwords are easily guessable and should be avoided."
        )
        info_label.setWordWrap(True)
        
        # Password input
        input_layout = QHBoxLayout()
        self.common_pw_input = QLineEdit()
        self.common_pw_input.setPlaceholderText("Enter password to check")
        check_btn = QPushButton("Check")
        check_btn.clicked.connect(self.check_common_password)
        
        input_layout.addWidget(self.common_pw_input)
        input_layout.addWidget(check_btn)
        
        # Results
        self.common_pw_result = QLabel()
        self.common_pw_result.setWordWrap(True)
        
        layout.addWidget(info_label)
        layout.addLayout(input_layout)
        layout.addWidget(self.common_pw_result)
        layout.addStretch()
        
        self.common_pw_tab.setLayout(layout)
    
    def setup_policy_ui(self):
        """Set up UI for password policy checking"""
        layout = QVBoxLayout()
        
        # Policy settings
        policy_group = QGroupBox("Password Policy Settings")
        policy_layout = QFormLayout()
        
        self.min_length = QSpinBox()
        self.min_length.setRange(1, 64)
        self.min_length.setValue(8)
        
        self.require_upper = QCheckBox()
        self.require_upper.setChecked(True)
        
        self.require_lower = QCheckBox()
        self.require_lower.setChecked(True)
        
        self.require_digit = QCheckBox()
        self.require_digit.setChecked(True)
        
        self.require_special = QCheckBox()
        self.require_special.setChecked(True)
        
        policy_layout.addRow("Minimum Length:", self.min_length)
        policy_layout.addRow("Require Uppercase:", self.require_upper)
        policy_layout.addRow("Require Lowercase:", self.require_lower)
        policy_layout.addRow("Require Digit:", self.require_digit)
        policy_layout.addRow("Require Special Char:", self.require_special)
        policy_group.setLayout(policy_layout)
        
        # Test password
        test_layout = QHBoxLayout()
        self.policy_pw_input = QLineEdit()
        self.policy_pw_input.setPlaceholderText("Enter password to check against policy")
        test_btn = QPushButton("Check")
        test_btn.clicked.connect(self.check_password_policy)
        
        test_layout.addWidget(self.policy_pw_input)
        test_layout.addWidget(test_btn)
        
        # Results
        self.policy_result = QTextEdit()
        self.policy_result.setReadOnly(True)
        
        layout.addWidget(policy_group)
        layout.addLayout(test_layout)
        layout.addWidget(QLabel("Policy Check Results:"))
        layout.addWidget(self.policy_result)
        
        self.policy_tab.setLayout(layout)
    
    def test_single_password(self):
        """Test a single password for various security issues"""
        password = self.password_input.text()
        if not password:
            self.results_text.setPlainText("Please enter a password to test.")
            return
        
        results = []
        
        # Check password length
        length = len(password)
        results.append(f"• Length: {length} characters")
        
        # Check character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        results.append("• Character types:")
        results.append(f"  - Uppercase letters: {'✓' if has_upper else '✗'}")
        results.append(f"  - Lowercase letters: {'✓' if has_lower else '✗'}")
        results.append(f"  - Digits: {'✓' if has_digit else '✗'}")
        results.append(f"  - Special characters: {'✓' if has_special else '✗'}")
        
        # Check against common passwords
        if password.lower() in self.common_passwords:
            results.append("• Security: ❌ Password is too common")
        else:
            results.append("• Security: ✅ Not found in common password lists")
        
        # Calculate password strength
        strength = self.calculate_strength(password)
        results.append(f"• Estimated strength: {strength}")
        
        # Display results
        self.results_text.setPlainText("\n".join(results))
    
    def test_password_list(self):
        """Test a list of passwords from a file"""
        file_path = self.file_path_edit.text()
        if not file_path or not os.path.isfile(file_path):
            self.show_error("Please select a valid password file.")
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.show_error(f"Error reading password file: {e}")
            return
        
        if not passwords:
            self.show_error("The selected file is empty.")
            return
        
        # Setup progress bar
        self.progress_bar.setMaximum(len(passwords))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        
        # Clear previous results
        self.results_table.setRowCount(0)
        
        # Process passwords
        for i, password in enumerate(passwords):
            # Update progress
            self.progress_bar.setValue(i + 1)
            
            # Skip empty passwords
            if not password:
                continue
            
            # Check password
            issues = []
            
            # Check against common passwords
            if self.check_common.isChecked() and password.lower() in self.common_passwords:
                issues.append("Common password")
            
            # Check against policy if enabled
            if self.check_policy.isChecked():
                policy_issues = self.check_password_policy_internal(
                    password,
                    self.min_length.value(),
                    self.require_upper.isChecked(),
                    self.require_lower.isChecked(),
                    self.require_digit.isChecked(),
                    self.require_special.isChecked()
                )
                issues.extend(policy_issues)
            
            # Calculate strength
            strength = self.calculate_strength(password)
            
            # Add to results table
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            # Mask the password for display
            masked_pw = password[0] + '*' * (len(password) - 2) + (password[-1] if len(password) > 1 else '')
            
            self.results_table.setItem(row, 0, QTableWidgetItem(masked_pw))
            self.results_table.setItem(row, 1, QTableWidgetItem(strength))
            self.results_table.setItem(row, 2, QTableWidgetItem(", ".join(issues) if issues else "No issues"))
            
            # Process events to update the UI
            QApplication.processEvents()
        
        # Hide progress bar when done
        self.progress_bar.setVisible(False)
    
    def check_common_password(self):
        """Check if a password is in the common passwords list"""
        password = self.common_pw_input.text()
        if not password:
            self.common_pw_result.setText("Please enter a password to check.")
            return
        
        if password.lower() in self.common_passwords:
            self.common_pw_result.setText(
                "❌ This password is in the list of commonly used passwords.\n"
                "It would be easily guessable in a dictionary attack."
            )
        else:
            self.common_pw_result.setText(
                "✅ This password is not in the list of most common passwords.\n"
                "However, this doesn't guarantee it's a strong password."
            )
    
    def check_password_policy(self):
        """Check a password against the current policy settings"""
        password = self.policy_pw_input.text()
        if not password:
            self.policy_result.setPlainText("Please enter a password to check.")
            return
        
        issues = self.check_password_policy_internal(
            password,
            self.min_length.value(),
            self.require_upper.isChecked(),
            self.require_lower.isChecked(),
            self.require_digit.isChecked(),
            self.require_special.isChecked()
        )
        
        if not issues:
            self.policy_result.setPlainText("✅ This password meets all the policy requirements.")
        else:
            result = ["❌ The password does not meet the following requirements:", ""]
            for issue in issues:
                result.append(f"• {issue}")
            self.policy_result.setPlainText("\n".join(result))
    
    def check_password_policy_internal(self, password: str, min_length: int, 
                                     require_upper: bool, require_lower: bool,
                                     require_digit: bool, require_special: bool) -> list:
        """Check a password against the specified policy"""
        issues = []
        
        if len(password) < min_length:
            issues.append(f"Password must be at least {min_length} characters long")
        
        if require_upper and not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if require_lower and not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if require_digit and not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one digit")
        
        if require_special and not any(not c.isalnum() for c in password):
            issues.append("Password must contain at least one special character")
        
        return issues
    
    def calculate_strength(self, password: str) -> str:
        """Calculate and return a strength rating for the password"""
        if not password:
            return "Very Weak"
        
        score = 0
        length = len(password)
        
        # Length score
        if length < 8:
            score += 0
        elif length < 12:
            score += 1
        else:
            score += 2
        
        # Character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Add points for each character type
        char_types = sum([has_upper, has_lower, has_digit, has_special])
        score += char_types - 1  # 0-3 points
        
        # Check for common patterns
        common_patterns = [
            r'^[0-9]+$',  # All digits
            r'^[a-zA-Z]+$',  # All letters
            r'^[a-z]+$',  # All lowercase
            r'^[A-Z]+$',  # All uppercase
            r'^[!@#$%^&*()_+]+$',  # All special chars
            r'^(.)\1+$',  # All same character
            r'123456', 'password', 'qwerty', 'letmein', 'welcome'  # Common passwords
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                score = max(0, score - 1)
                break
        
        # Determine strength
        if score <= 1:
            return "Very Weak"
        elif score == 2:
            return "Weak"
        elif score == 3:
            return "Moderate"
        elif score == 4:
            return "Strong"
        else:
            return "Very Strong"
    
    def browse_password_file(self):
        """Open a file dialog to select a password file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Password File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def show_error(self, message: str):
        """Display an error message"""
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(self, "Error", message)


class AuthProtocolTester(QWidget):
    """Widget for testing authentication protocols"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.protocol_workers = {}
    
    def setup_ui(self):
        """Set up the authentication protocol testing UI"""
        layout = QVBoxLayout()
        
        # Protocol selection
        protocol_group = QGroupBox("Authentication Protocol")
        protocol_layout = QHBoxLayout()
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["HTTP Basic Auth", "OAuth 2.0", "JWT", "LDAP", "NTLM", "Kerberos"])
        
        protocol_layout.addWidget(QLabel("Select Protocol:"))
        protocol_layout.addWidget(self.protocol_combo)
        protocol_group.setLayout(protocol_layout)
        
        # Configuration area
        config_group = QGroupBox("Configuration")
        self.config_layout = QFormLayout()
        
        # Common fields
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://example.com/api/endpoint")
        self.username = QLineEdit()
        self.username.setPlaceholderText("username or email")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password_file = QLineEdit()
        self.password_file.setPlaceholderText("Path to password file")
        
        # Add common fields
        self.config_layout.addRow("Target URL:", self.target_url)
        self.config_layout.addRow("Username:", self.username)
        self.config_layout.addRow("Password:", self.password)
        self.config_layout.addRow("Password File:", self.password_file)
        
        # Protocol-specific config will be added here
        self.protocol_config = QWidget()
        self.protocol_config_layout = QFormLayout()
        self.protocol_config.setLayout(self.protocol_config_layout)
        self.config_layout.addRow(self.protocol_config)
        
        # Add protocol-specific fields when protocol changes
        self.protocol_combo.currentTextChanged.connect(self.update_protocol_config)
        self.update_protocol_config()
        
        config_group.setLayout(self.config_layout)
        
        # Test controls
        controls_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Test")
        self.start_btn.clicked.connect(self.start_test)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_test)
        
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_layout.addStretch()
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        
        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        
        # Add to main layout
        layout.addWidget(protocol_group)
        layout.addWidget(config_group)
        layout.addLayout(controls_layout)
        layout.addWidget(self.progress)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results)
        
        self.setLayout(layout)
    
    def update_protocol_config(self):
        """Update the configuration UI based on the selected protocol"""
        # Clear previous config
        while self.protocol_config_layout.count():
            item = self.protocol_config_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        protocol = self.protocol_combo.currentText()
        
        if protocol == "HTTP Basic Auth":
            # No additional config needed for basic auth
            pass
        elif protocol == "OAuth 2.0":
            self.oauth_client_id = QLineEdit()
            self.oauth_client_secret = QLineEdit()
            self.oauth_scope = QLineEdit()
            self.oauth_scope.setText("openid profile email")
            
            self.protocol_config_layout.addRow("Client ID:", self.oauth_client_id)
            self.protocol_config_layout.addRow("Client Secret:", self.oauth_client_secret)
            self.protocol_config_layout.addRow("Scope:", self.oauth_scope)
        
        # Add more protocol-specific configurations here
    
    def start_test(self):
        """Start the authentication protocol test"""
        protocol = self.protocol_combo.currentText()
        self.results.append(f"Starting {protocol} test...\n")
        
        # Create and start a worker thread for the test
        worker = AuthTestWorker(protocol, self.get_test_config())
        worker.progress_updated.connect(self.update_progress)
        worker.test_completed.connect(self.test_completed)
        worker.error_occurred.connect(self.handle_error)
        
        # Store reference to worker
        worker_id = id(worker)
        self.protocol_workers[worker_id] = worker
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        
        # Start the worker
        worker.start()
    
    def stop_test(self):
        """Stop the currently running test"""
        for worker_id, worker in list(self.protocol_workers.items()):
            if worker.isRunning():
                worker.stop()
                self.protocol_workers.pop(worker_id, None)
        
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setVisible(False)
    
    def get_test_config(self):
        """Get the current test configuration"""
        return {
            'protocol': self.protocol_combo.currentText(),
            'target_url': self.target_url.text(),
            'username': self.username.text(),
            'password': self.password.text(),
            'password_file': self.password_file.text(),
            # Add protocol-specific config here
        }
    
    def update_progress(self, value, message):
        """Update the progress bar and results"""
        self.progress.setValue(value)
        if message:
            self.results.append(message)
    
    def test_completed(self, results):
        """Handle test completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setValue(100)
        
        # Display results
        self.results.append("\n=== Test Completed ===")
        self.results.append(f"Status: {results.get('status', 'Unknown')}")
        
        if 'findings' in results:
            self.results.append("\nSecurity Findings:")
            for finding in results['findings']:
                self.results.append(f"- {finding}")
        
        # Generate a report
        self.generate_report(results)
    
    def handle_error(self, error):
        """Handle errors during testing"""
        self.results.append(f"\nError: {error}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setVisible(False)
    
    def generate_report(self, results):
        """Generate a security findings report"""
        # This could be expanded to save reports to disk
        self.results.append("\n=== Security Report ===")
        self.results.append(f"Tested Protocol: {results.get('protocol', 'N/A')}")
        self.results.append(f"Target: {results.get('target', 'N/A')}")
        self.results.append(f"Test Time: {results.get('timestamp', 'N/A')}")
        
        if 'findings' in results and results['findings']:
            self.results.append("\nSecurity Issues Found:")
            for i, finding in enumerate(results['findings'], 1):
                self.results.append(f"{i}. {finding}")
        else:
            self.results.append("\nNo security issues found.")


class BruteForceTester(QWidget):
    """Widget for brute force simulation"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.attack_thread = None
    
    def setup_ui(self):
        """Set up the brute force testing UI"""
        layout = QVBoxLayout()
        
        # Target configuration
        target_group = QGroupBox("Target Configuration")
        target_layout = QFormLayout()
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("https://example.com/login")
        self.username = QLineEdit()
        self.username.setPlaceholderText("username or leave empty for username enumeration")
        self.username_list = QLineEdit()
        self.username_list.setPlaceholderText("Path to username list file (optional)")
        self.password_list = QLineEdit()
        self.password_list.setPlaceholderText("Path to password list file")
        
        target_layout.addRow("Target URL:", self.target_url)
        target_layout.addRow("Username:", self.username)
        target_layout.addRow("Username List:", self.username_list)
        target_layout.addRow("Password List:", self.password_list)
        
        # Attack parameters
        params_group = QGroupBox("Attack Parameters")
        params_layout = QFormLayout()
        
        self.max_threads = QSpinBox()
        self.max_threads.setRange(1, 50)
        self.max_threads.setValue(5)
        
        self.delay = QSpinBox()
        self.delay.setRange(0, 10000)
        self.delay.setValue(100)
        self.delay.setSuffix(" ms")
        
        params_layout.addRow("Max Threads:", self.max_threads)
        params_layout.addRow("Delay Between Attempts:", self.delay)
        
        # Request configuration
        self.method = QComboBox()
        self.method.addItems(["POST", "GET", "PUT", "DELETE"])
        
        self.content_type = QComboBox()
        self.content_type.addItems(["application/x-www-form-urlencoded", "application/json"])
        
        params_layout.addRow("HTTP Method:", self.method)
        params_layout.addRow("Content-Type:", self.content_type)
        
        # Parameters
        self.params = QTextEdit()
        self.params.setPlaceholderText("Enter request parameters (one per line, format: key=value)")
        self.params.setMaximumHeight(100)
        
        params_layout.addRow("Parameters:", self.params)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_attack)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        
        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        
        # Add to layouts
        target_group.setLayout(target_layout)
        params_group.setLayout(params_layout)
        
        layout.addWidget(target_group)
        layout.addWidget(params_group)
        layout.addLayout(btn_layout)
        layout.addWidget(self.progress)
        layout.addWidget(QLabel("Results:"))
        layout.addWidget(self.results)
        
        self.setLayout(layout)
    
    def start_attack(self):
        """Start the brute force attack"""
        # Validate inputs
        if not self.target_url.text():
            self.show_error("Please enter a target URL")
            return
            
        if not os.path.exists(self.password_list.text()):
            self.show_error("Please select a valid password list file")
            return
            
        if self.username_list.text() and not os.path.exists(self.username_list.text()):
            self.show_error("Username list file not found")
            return
        
        # Parse parameters
        params = {}
        for line in self.params.toPlainText().split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                params[key.strip()] = value.strip()
        
        # Create attack configuration
        config = {
            'target_url': self.target_url.text(),
            'username': self.username.text(),
            'username_list': self.username_list.text(),
            'password_list': self.password_list.text(),
            'method': self.method.currentText(),
            'content_type': self.content_type.currentText(),
            'params': params,
            'max_threads': self.max_threads.value(),
            'delay': self.delay.value(),
        }
        
        # Create and start attack thread
        self.attack_thread = BruteForceWorker(config)
        self.attack_thread.progress_updated.connect(self.update_progress)
        self.attack_thread.credentials_found.connect(self.credentials_found)
        self.attack_thread.finished.connect(self.attack_finished)
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.results.clear()
        self.results.append("Starting brute force attack...\n")
        
        self.attack_thread.start()
    
    def stop_attack(self):
        """Stop the running attack"""
        if self.attack_thread and self.attack_thread.isRunning():
            self.attack_thread.stop()
            self.attack_thread.wait()
            self.attack_thread = None
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress.setVisible(False)
            
            self.results.append("\nAttack stopped by user.")
    
    def update_progress(self, current, total, current_attempt):
        """Update the progress bar and display current attempt"""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress.setValue(progress)
            
        if current_attempt:
            self.results.append(f"Trying: {current_attempt}")
            
            # Auto-scroll to bottom
            scrollbar = self.results.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
    
    def credentials_found(self, username, password):
        """Handle found credentials"""
        self.results.append(f"\n✅ Credentials found!")
        self.results.append(f"Username: {username}")
        self.results.append(f"Password: {password}")
        
        # Optionally stop the attack when credentials are found
        self.stop_attack()
    
    def attack_finished(self):
        """Handle attack completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setValue(100)
        
        self.results.append("\nBrute force attack completed.")
    
    def show_error(self, message):
        """Display an error message"""
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(self, "Error", message)


class SecurityReportGenerator:
    """Class for generating security reports"""
    
    @staticmethod
    def generate_html_report(findings, output_file=None):
        """Generate an HTML security report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Severity counts
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .severity-critical {{ color: #dc3545; font-weight: bold; }}
                .severity-high {{ color: #fd7e14; font-weight: bold; }}
                .severity-medium {{ color: #ffc107; font-weight: bold; }}
                .severity-low {{ color: #28a745; font-weight: bold; }}
                .severity-info {{ color: #17a2b8; }}
                .finding {{ margin-bottom: 15px; padding: 10px; border-left: 4px solid #ddd; }}
                .finding.critical {{ border-left-color: #dc3545; background-color: #fff5f5; }}
                .finding.high {{ border-left-color: #fd7e14; background-color: #fff8f0; }}
                .finding.medium {{ border-left-color: #ffc107; background-color: #fffce6; }}
                .finding.low {{ border-left-color: #28a745; background-color: #f0fff4; }}
                .finding.info {{ border-left-color: #17a2b8; background-color: #f0f9ff; }}
                .severity-badge {{ 
                    display: inline-block; 
                    padding: 2px 8px; 
                    border-radius: 10px; 
                    font-size: 0.8em; 
                    font-weight: bold; 
                    color: white; 
                    margin-right: 10px;
                }}
                .critical-bg {{ background-color: #dc3545; }}
                .high-bg {{ background-color: #fd7e14; }}
                .medium-bg {{ background-color: #ffc107; }}
                .low-bg {{ background-color: #28a745; }}
                .info-bg {{ background-color: #17a2b8; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f8f9fa; }}
                .timestamp {{ color: #6c757d; font-size: 0.9em; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <div class="timestamp">Generated on: {timestamp}</div>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>This report summarizes the security findings from the authentication and password testing.</p>
                
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
                    <tr>
                        <td><span class="severity-critical">Critical</span></td>
                        <td>{critical_count}</td>
                    </tr>
                    <tr>
                        <td><span class="severity-high">High</span></td>
                        <td>{high_count}</td>
                    </tr>
                    <tr>
                        <td><span class="severity-medium">Medium</span></td>
                        <td>{medium_count}</td>
                    </tr>
                    <tr>
                        <td><span class="severity-low">Low</span></td>
                        <td>{low_count}</td>
                    </tr>
                    <tr>
                        <td><span class="severity-info">Info</span></td>
                        <td>{info_count}</td>
                    </tr>
                </table>
            </div>
            
            <h2>Detailed Findings</h2>
        """.format(
            timestamp=timestamp,
            critical_count=severity_counts['Critical'],
            high_count=severity_counts['High'],
            medium_count=severity_counts['Medium'],
            low_count=severity_counts['Low'],
            info_count=severity_counts['Info']
        )
        
        # Add findings
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'Info').lower()
            html += f"""
            <div class="finding {severity}">
                <h3>
                    <span class="severity-badge {severity}-bg">{finding.get('severity', 'Info')}</span>
                    {finding.get('title', 'Finding #{0}').format(i)}
                </h3>
                <p><strong>Description:</strong> {finding.get('description', 'No description provided.')}</p>
                <p><strong>Impact:</strong> {finding.get('impact', 'Not specified.')}</p>
                <p><strong>Recommendation:</strong> {finding.get('recommendation', 'No recommendation provided.')}</p>
                <p><strong>Details:</strong><br>{finding.get('details', 'No additional details.')}</p>
            </div>
            """
        
        # Close HTML
        html += """
            <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; color: #6c757d; font-size: 0.9em;">
                <p>Report generated by Hack Attack Security Testing Suite</p>
            </div>
        </body>
        </html>
        """
        
        # Save to file if output path is provided
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html)
                return True, f"Report saved to {output_file}"
            except Exception as e:
                return False, f"Failed to save report: {str(e)}"
        
        return True, html


class AuthTestWorker(QThread):
    """Worker thread for authentication protocol testing"""
    
    progress_updated = Signal(int, str)
    test_completed = Signal(dict)
    error_occurred = Signal(str)
    
    def __init__(self, protocol, config):
        super().__init__()
        self.protocol = protocol
        self.config = config
        self._is_running = True
    
    def run(self):
        """Run the authentication test"""
        try:
            self.progress_updated.emit(10, f"Starting {self.protocol} test...")
            
            # Simulate test progress
            for i in range(10, 100, 10):
                if not self._is_running:
                    return
                
                self.progress_updated.emit(
                    i, 
                    f"Testing {self.protocol} (step {i//10}/10)..."
                )
                self.msleep(500)  # Simulate work
            
            # Simulate test results
            results = {
                'status': 'Completed',
                'protocol': self.protocol,
                'target': self.config.get('target_url', 'N/A'),
                'timestamp': datetime.now().isoformat(),
                'findings': [
                    f"Potential weak cipher suite detected in {self.protocol} handshake",
                    f"Missing security headers in {self.protocol} response",
                    f"Possible information leakage in {self.protocol} error messages"
                ]
            }
            
            self.test_completed.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def stop(self):
        """Stop the test"""
        self._is_running = False
        self.wait()


class BruteForceWorker(QThread):
    """Worker thread for brute force attacks"""
    
    progress_updated = Signal(int, int, str)  # current, total, current_attempt
    credentials_found = Signal(str, str)  # username, password
    
    def __init__(self, config):
        super().__init__()
        self.config = config
        self._is_running = True
    
    def run(self):
        """Run the brute force attack"""
        try:
            # Load usernames
            usernames = []
            if self.config['username_list'] and os.path.exists(self.config['username_list']):
                with open(self.config['username_list'], 'r', encoding='utf-8', errors='ignore') as f:
                    usernames = [line.strip() for line in f if line.strip()]
            elif self.config['username']:
                usernames = [self.config['username']]
            
            # Load passwords
            with open(self.config['password_list'], 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not usernames or not passwords:
                self.error_occurred.emit("No usernames or passwords to test")
                return
            
            total_attempts = len(usernames) * len(passwords)
            current_attempt = 0
            
            # Simulate brute force attack
            for username in usernames:
                for password in passwords:
                    if not self._is_running:
                        return
                    
                    current_attempt += 1
                    attempt = f"{username}:{password}"
                    self.progress_updated.emit(current_attempt, total_attempts, attempt)
                    
                    # Simulate network delay
                    self.msleep(self.config.get('delay', 100))
                    
                    # Simulate finding credentials (10% chance for demo)
                    if current_attempt % 10 == 0 and current_attempt > 0:
                        self.credentials_found.emit(username, password)
                        return
            
        except Exception as e:
            self.error_occurred.emit(str(e))
    
    def stop(self):
        """Stop the attack"""
        self._is_running = False
        self.wait()


class AuthTestingGUI(QWidget):
    """Main GUI for Authentication & Password Testing module"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.findings = []
    
    def setup_ui(self):
        """Set up the user interface"""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Authentication & Password Testing")
        header.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 15px;")
        
        # Description
        desc = QLabel(
            "This module provides tools for testing authentication mechanisms and password security. "
            "Use the tabs below to access different testing tools."
        )
        desc.setWordWrap(True)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Add password tester tab
        self.password_tester = PasswordTester()
        self.tabs.addTab(self.password_tester, "Password Testing")
        
        # Add authentication protocol testing tab
        self.auth_tester = AuthProtocolTester()
        self.tabs.addTab(self.auth_tester, "Authentication Testing")
        
        # Add brute force testing tab
        self.brute_force_tester = BruteForceTester()
        self.tabs.addTab(self.brute_force_tester, "Brute Force Simulation")
        
        # Add report generation button
        report_btn = QPushButton("Generate Security Report")
        report_btn.clicked.connect(self.generate_security_report)
        
        # Add to main layout
        layout.addWidget(header)
        layout.addWidget(desc)
        layout.addSpacing(10)
        layout.addWidget(self.tabs)
        layout.addWidget(report_btn, alignment=Qt.AlignRight)
        
        self.setLayout(layout)
    
    def generate_security_report(self):
        """Generate a security report with all findings"""
        # Collect findings from all testers
        findings = []
        
        # Add password policy findings
        password_findings = self.password_tester.get_security_findings()
        findings.extend(password_findings)
        
        # Add authentication testing findings
        auth_findings = self.auth_tester.get_security_findings()
        findings.extend(auth_findings)
        
        # Add brute force findings
        brute_force_findings = self.brute_force_tester.get_security_findings()
        findings.extend(brute_force_findings)
        
        if not findings:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Findings", "No security findings to report.")
            return
        
        # Generate HTML report
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Security Report",
            f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;All Files (*)"
        )
        
        if file_name:
            success, message = SecurityReportGenerator.generate_html_report(findings, file_name)
            
            if success:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(self, "Report Generated", 
                    f"Security report saved successfully.\n\n{message}")
                
                # Optionally open the report in the default browser
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(file_name)}")
            else:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Error", f"Failed to generate report: {message}")


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = AuthTestingGUI()
    window.setWindowTitle("Authentication & Password Testing")
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec_())
