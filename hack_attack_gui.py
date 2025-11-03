import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QListWidget, QListWidgetItem, 
                             QStackedWidget, QStatusBar, QPushButton, QTextEdit,
                             QFileDialog, QMessageBox)
from PySide6.QtCore import Qt, QSize, Signal as pyqtSignal, QTimer, QDateTime
from PySide6.QtGui import QIcon, QFont

class HackAttackGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hack Attack - Professional Security Testing Suite")
        self.setMinimumSize(1200, 800)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
            QListWidget {
                background-color: #181825;
                border: none;
                font-size: 13px;
                padding: 10px 5px;
                min-width: 280px;
                max-width: 300px;
            }
            QListWidget::item {
                padding: 10px 8px;
                border-radius: 5px;
                margin: 2px 0;
                min-height: 50px;
            }
            QListWidget::item:selected {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
            QLabel {
                font-size: 18px;
                padding: 20px;
            }
            QStatusBar {
                background-color: #181825;
                color: #a6adc8;
            }
        """)
        
        # Create main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        
        # Create sidebar
        self.create_sidebar()
        
        # Create main content area
        self.create_main_content()
        
        # Setup status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def create_sidebar(self):
        """Create the sidebar navigation"""
        self.sidebar = QListWidget()
        self.sidebar.setMinimumWidth(280)
        self.sidebar.setMaximumWidth(300)
        self.sidebar.setWordWrap(True)
        
        # Add navigation items
        nav_items = [
            "Dashboard",
            "Device Discovery & Info",
            "Network & Protocol Analysis",
            "Firmware & OS Analysis",
            "Authentication & Password Testing",
            "Exploitation & Payloads",
            "Mobile & Embedded Tools",
            "Forensics & Incident Response",
            "Settings & Reports",
            "Automation & Scripting",
            "Logs & History",
            "Help & Documentation"
        ]
        
        self.sidebar.addItems(nav_items)
        self.sidebar.currentRowChanged.connect(self.change_page)
        self.main_layout.addWidget(self.sidebar)
    
    def create_placeholder_page(self, title, description, icon_name):
        """Create a modern module page with icon and description"""
        page = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(15)
        
        # Header with icon and title
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 20)
        
        # Icon (using text as fallback)
        icon_label = QLabel(icon_name)
        icon_label.setStyleSheet("""
            font-size: 36px;
            color: #89b4fa;
            padding: 15px;
            background-color: rgba(137, 180, 250, 0.1);
            border-radius: 10px;
        """)
        header_layout.addWidget(icon_label)
        
        # Title
        title_label = QLabel(f"<h1 style='margin: 0; color: #cdd6f4;'>{title}</h1>")
        title_label.setStyleSheet("font-size: 24px;")
        header_layout.addWidget(title_label, 1)
        
        layout.addWidget(header)
        
        # Description card
        desc_card = QWidget()
        desc_card.setStyleSheet("""
            background-color: #313244;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #89b4fa;
        """)
        desc_layout = QVBoxLayout(desc_card)
        
        desc_text = QLabel(description)
        desc_text.setWordWrap(True)
        desc_text.setStyleSheet("color: #cdd6f4; font-size: 14px; line-height: 1.5;")
        desc_layout.addWidget(desc_text)
        
        layout.addWidget(desc_card)
        
        # Add module-specific content
        if title == "Dashboard":
            # Create a grid layout for dashboard widgets
            grid = QVBoxLayout()
            grid.setSpacing(15)
            
            # Welcome card
            welcome_card = QWidget()
            welcome_card.setStyleSheet("""
                background: linear-gradient(135deg, #1e1e2e 0%, #313244 100%);
                border-radius: 10px;
                padding: 20px;
                border-left: 4px solid #89b4fa;
            """)
            welcome_layout = QVBoxLayout(welcome_card)
            welcome_title = QLabel("Welcome to Hack Attack")
            welcome_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #89b4fa; margin-bottom: 10px;")
            welcome_text = QLabel("Professional Security Testing Suite - v1.0.0")
            welcome_text.setStyleSheet("color: #cdd6f4; font-size: 14px;")
            welcome_layout.addWidget(welcome_title)
            welcome_layout.addWidget(welcome_text)
            grid.addWidget(welcome_card)
            
            # Activity log to show messages
            self.activity_log = QTextEdit()
            self.activity_log.setReadOnly(True)
            self.activity_log.setStyleSheet("""
                QTextEdit {
                    background-color: #181825;
                    border: 1px solid #313244;
                    border-radius: 5px;
                    padding: 10px;
                    color: #cdd6f4;
                    font-family: monospace;
                }
            """)
            self.activity_log.setPlaceholderText("No recent activity")
            self.activity_log.setMaximumHeight(150)
            grid.addWidget(self.activity_log)
            
            # Stats row
            stats_layout = QHBoxLayout()
            stats_layout.setSpacing(15)
            
            def create_stat_card(title, value, color):
                card = QWidget()
                card.setStyleSheet(f"""
                    background-color: #1e1e2e;
                    border-radius: 8px;
                    padding: 15px;
                    border-left: 4px solid {color};
                """)
                layout = QVBoxLayout(card)
                value_label = QLabel(str(value))
                value_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #cdd6f4;")
                title_label = QLabel(title)
                title_label.setStyleSheet("font-size: 12px; color: #a6adc8; margin-top: 5px;")
                layout.addWidget(value_label)
                layout.addWidget(title_label)
                return card
            
            # Add stat cards
            stats_layout.addWidget(create_stat_card("Active Scans", "0", "#f38ba8"))
            stats_layout.addWidget(create_stat_card("Devices Found", "0", "#a6e3a1"))
            stats_layout.addWidget(create_stat_card("Vulnerabilities", "0", "#f9e2af"))
            stats_layout.addWidget(create_stat_card("Tasks Completed", "0", "#89b4fa"))
            
            grid.addLayout(stats_layout)
            
            # Quick Actions
            actions_card = QWidget()
            actions_card.setStyleSheet("""
                background-color: #1e1e2e;
                border-radius: 10px;
                padding: 20px;
            """)
            actions_layout = QVBoxLayout(actions_card)
            actions_title = QLabel("Quick Actions")
            actions_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa; margin-bottom: 10px;")
            actions_layout.addWidget(actions_title)
            
            # Quick action buttons
            buttons_layout = QHBoxLayout()
            buttons_layout.setSpacing(10)
            
            def create_action_button(text, color, tooltip=None):
                btn = QPushButton(text)
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {color};
                        color: #1e1e2e;
                        border: none;
                        padding: 10px 15px;
                        border-radius: 5px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        opacity: 0.9;
                    }}
                    QPushButton:disabled {{
                        background-color: #6c7086;
                        color: #a6adc8;
                    }}
                """)
                if tooltip:
                    btn.setToolTip(tooltip)
                return btn
            
            # Quick Scan button
            scan_btn = create_action_button(
                "🔍 Quick Scan", 
                "#89b4fa",
                "Perform a quick network scan for devices"
            )
            scan_btn.clicked.connect(self.start_quick_scan)
            
            # Generate Report button
            report_btn = create_action_button(
                "📊 Generate Report", 
                "#a6e3a1",
                "Generate a detailed security report"
            )
            report_btn.clicked.connect(self.generate_report)
            
            # Settings button
            settings_btn = create_action_button(
                "⚙️ Settings", 
                "#f9e2af",
                "Open application settings"
            )
            settings_btn.clicked.connect(self.open_settings)
            
            buttons_layout.addWidget(scan_btn)
            buttons_layout.addWidget(report_btn)
            buttons_layout.addWidget(settings_btn)
            buttons_layout.addStretch()
            
            actions_layout.addLayout(buttons_layout)
            actions_layout.addStretch()
            
            # Add recent activity
            activity_title = QLabel("Recent Activity")
            activity_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #89b4fa; margin: 15px 0 10px 0;")
            actions_layout.addWidget(activity_title)
            
            self.activity_log = QTextEdit()
            self.activity_log.setReadOnly(True)
            self.activity_log.setStyleSheet("""
                QTextEdit {
                    background-color: #181825;
                    border: 1px solid #313244;
                    border-radius: 5px;
                    padding: 10px;
                    color: #cdd6f4;
                    font-family: monospace;
                }
            """)
            self.activity_log.setPlaceholderText("No recent activity")
            self.activity_log.setMaximumHeight(150)
            actions_layout.addWidget(self.activity_log)
            
            grid.addWidget(actions_card)
            
            # Add the grid to the main layout
            layout.addLayout(grid)
            
        elif title == "Device Discovery & Info":
            from modules.device_discovery import DeviceDiscoveryGUI
            
            # Create and add the full DeviceDiscoveryGUI
            self.device_discovery_gui = DeviceDiscoveryGUI()
            
            # Remove margins and add to layout
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)
            layout.addWidget(self.device_discovery_gui)
            
        elif title == "Network & Protocol Analysis":
            from modules.network_analysis import NetworkAnalysisGUI
            
            # Create and add the NetworkAnalysisGUI
            self.network_analysis_gui = NetworkAnalysisGUI()
            
            # Remove margins and add to layout
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)
            layout.addWidget(self.network_analysis_gui)
            
        else:
            # Default banner for other modules
            banner = QLabel("🚀 Coming Soon")
            banner.setStyleSheet("""
                background: linear-gradient(90deg, #1e1e2e, #313244);
                color: #a6e3a1;
                font-weight: bold;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                font-size: 16px;
                border: 1px solid #45475a;
                margin-top: 20px;
            """)
            layout.addWidget(banner)
        
        # Add some space at the bottom
        layout.addStretch()
        
        page.setLayout(layout)
        return page
        
    def create_main_content(self):
        """Create the main content area with stacked widgets"""
        self.stacked_widget = QStackedWidget()
        
        # Module descriptions
        module_descriptions = [
            ("Dashboard", "Monitor your security assessment activities, view system status, and access quick actions.", "📊"),
            ("Device Discovery & Info", "Scan and analyze connected devices on your network, including detailed hardware and software information.", "🔍"),
            ("Network & Protocol Analysis", "Analyze network traffic, perform protocol analysis, and identify vulnerabilities.", "🌐"),
            ("Firmware & OS Analysis", "Inspect firmware images, analyze operating systems, and identify potential security issues.", "💾"),
            ("Authentication & Password Testing", "Test authentication mechanisms and perform password security assessments.", "🔑"),
            ("Exploitation & Payloads", "Develop and manage exploits and payloads for security testing purposes.", "⚡"),
            ("Mobile & Embedded Tools", "Specialized tools for testing mobile and embedded device security.", "📱"),
            ("Forensics & Incident Response", "Investigate security incidents and perform digital forensics.", "🔍"),
            ("Settings & Reports", "Configure application settings and generate detailed security reports.", "⚙️"),
            ("Automation & Scripting", "Create and manage automated security testing workflows.", "🤖"),
            ("Logs & History", "View detailed logs and history of all security testing activities.", "📝"),
            ("Help & Documentation", "Access user guides, tutorials, and API documentation.", "❓")
        ]
        
        # Create a page for each module
        for i, (title, desc, icon) in enumerate(module_descriptions):
            page = self.create_placeholder_page(title, desc, icon)
            self.stacked_widget.addWidget(page)
        
        self.main_layout.addWidget(self.stacked_widget, 1)
    
    def change_page(self, index):
        """Change the current page based on sidebar selection"""
        if 0 <= index < self.stacked_widget.count():
            self.stacked_widget.setCurrentIndex(index)
            self.status_bar.showMessage(f"Switched to: {self.sidebar.currentItem().text()}")
    
    def log_activity(self, message):
        """Add a message to the activity log"""
        if hasattr(self, 'activity_log') and self.activity_log:
            timestamp = QDateTime.currentDateTime().toString("[yyyy-MM-dd hh:mm:ss]")
            self.activity_log.append(f"{timestamp} {message}")
            # Scroll to bottom
            self.activity_log.verticalScrollBar().setValue(
                self.activity_log.verticalScrollBar().maximum()
            )
    
    def start_quick_scan(self):
        """Handle quick scan button click"""
        self.log_activity("🔍 Starting quick network scan...")
        # Here you would integrate with your scanning functionality
        # For now, we'll just simulate a scan
        QTimer.singleShot(2000, self.on_quick_scan_complete)
    
    def on_quick_scan_complete(self):
        """Called when quick scan completes"""
        self.log_activity("✅ Quick scan completed")
        self.log_activity("   Found 5 devices on the network")
        self.log_activity("   Scan results available in Device Discovery")
        
        # Switch to device discovery tab
        self.sidebar.setCurrentRow(1)  # Assuming Device Discovery is the second item
    
    def generate_report(self):
        """Handle generate report button click"""
        self.log_activity("📄 Generating security report...")
        # Here you would implement report generation
        QTimer.singleShot(1500, lambda: self.log_activity("📄 Report generated: report_2025-11-03.html"))
    
    def open_settings(self):
        """Handle settings button click"""
        self.log_activity("⚙️ Opening settings...")
        # Switch to settings tab (assuming it's the 9th item, 0-indexed)
        if self.sidebar.count() > 8:  # Make sure settings tab exists
            self.sidebar.setCurrentRow(8)  # Settings tab index
    
    def run_device_scan(self):
        """This method is no longer used as we're using the full DeviceDiscoveryGUI"""
        pass

def main():
    app = QApplication(sys.argv)
    
    # Set application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = HackAttackGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
