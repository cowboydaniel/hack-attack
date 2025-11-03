"""
Network & Protocol Analysis Module for Hack Attack

This module provides comprehensive network traffic analysis and protocol inspection
capabilities for security testing and ethical hacking purposes.
"""

import json
import subprocess
import re
import logging
import socket
import struct
import time
import threading
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union, Callable

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to see all messages
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Set log level for other modules to WARNING to reduce noise
logging.getLogger('scapy').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Log environment information
logger.debug("Python version: %s", os.sys.version)
logger.debug("Current working directory: %s", os.getcwd())

# Network capture dependencies
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Please install with: pip install scapy")

# GUI Dependencies
from PySide6.QtCore import QThread, Signal as pyqtSignal, Qt, QSize, QTimer, Slot as pyqtSlot, QMetaObject, Q_ARG
from PySide6.QtGui import QIcon, QFont, QColor, QAction, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTreeWidget, QTreeWidgetItem, QTabWidget, QLabel,
    QStatusBar, QMessageBox, QFileDialog, QTableWidget, QTableWidgetItem,
    QLineEdit, QProgressBar, QHeaderView, QStyle, QMenu, QSplitter,
    QComboBox, QFormLayout, QGroupBox, QCheckBox, QTextEdit, QSpinBox, QFrame
)

class NetworkAnalyzer:
    """Main class for network traffic analysis and protocol inspection."""
    
    def __init__(self):
        """Initialize the NetworkAnalyzer class."""
        self.capture_active = threading.Event()
        self.packets = []
        self.capture_filter = ""
        self.interface = self._get_default_interface()
        self.packet_callback = None
    
    def get_available_interfaces(self) -> List[str]:
        """Get a list of available network interfaces."""
        interfaces = []
        
        # Try to get interfaces using scapy
        if SCAPY_AVAILABLE:
            try:
                ifaces = get_working_ifaces()
                if hasattr(ifaces, 'keys'):
                    return list(ifaces.keys())
                else:
                    # Handle case where ifaces is already a list
                    return [iface.name for iface in ifaces if hasattr(iface, 'name')]
            except Exception as e:
                logger.warning(f"Could not get interfaces with scapy: {e}")
        
        # Fallback to netifaces
        try:
            import netifaces
            return netifaces.interfaces()
        except Exception as e:
            logger.error(f"Could not get interfaces with netifaces: {e}")
            
        # Final fallback to common interface names
        return ["eth0", "wlan0", "lo"]
    
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        if not SCAPY_AVAILABLE:
            return "eth0"
            
        try:
            # Get default gateway interface
            import netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            
            # Verify the interface exists
            if default_gateway in self.get_available_interfaces():
                return default_gateway
                
            # Fallback to first non-loopback interface
            for iface in self.get_available_interfaces():
                if iface != 'lo' and not iface.startswith('docker') and not iface.startswith('br-'):
                    return iface
                    
            return "eth0"  # Final fallback
            
        except Exception as e:
            logger.error(f"Could not determine default interface: {e}")
            available = self.get_available_interfaces()
            return available[0] if available else "eth0"
    
    def set_interface(self, interface: str) -> None:
        """Set the network interface to capture on."""
        self.interface = interface
        if SCAPY_AVAILABLE:
            conf.iface = interface
    
    def set_capture_filter(self, capture_filter: str) -> None:
        """Set the capture filter (BPF syntax)."""
        self.capture_filter = capture_filter
    
    def start_capture(self) -> bool:
        """Start capturing network traffic."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not available. Cannot start capture.")
            return False
            
        try:
            logger.info(f"Starting capture on interface {self.interface} with filter: {self.capture_filter}")
            logger.info(f"Available interfaces: {self.get_available_interfaces()}")
            
            # Verify the interface exists
            if self.interface not in self.get_available_interfaces():
                logger.error(f"Interface {self.interface} not found in available interfaces")
                return False
                
            logger.info(f"Interface {self.interface} is valid")
            self.capture_active.set()
            return True
            
        except Exception as e:
            logger.exception("Failed to start capture")
            return False
    
    def stop_capture(self) -> None:
        """Stop the current capture."""
        self.capture_active.clear()
        logger.info("Capture stopped")
        
    def packet_handler(self, packet):
        """Process a captured packet."""
        # This method is kept for backward compatibility
        # The actual packet processing is now done in the CaptureThread._packet_callback method
        pass
    
    def set_packet_callback(self, callback: Callable[[Dict], None]) -> None:
        """Set a callback function to be called for each captured packet."""
        self.packet_callback = callback
    
    def get_capture_stats(self) -> Dict[str, int]:
        """Get statistics about the current capture."""
        return {
            'total_packets': len(self.packets),
            'tcp_packets': sum(1 for p in self.packets if p.get('protocol') == 'TCP'),
            'udp_packets': sum(1 for p in self.packets if p.get('protocol') == 'UDP'),
            'other_packets': sum(1 for p in self.packets if p.get('protocol') not in ['TCP', 'UDP'])
        }
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get the distribution of protocols in the captured traffic."""
        protocols = {}
        for packet in self.packets:
            proto = packet.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        return protocols
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the top talkers by packet count."""
        talkers = {}
        for packet in self.packets:
            src = packet.get('source')
            dst = packet.get('destination')
            if src and dst:
                key = f"{src} -> {dst}"
                talkers[key] = talkers.get(key, 0) + 1
        
        return [
            {'conversation': k, 'packet_count': v}
            for k, v in sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:limit]
        ]


class CaptureThread(QThread):
    """Thread for performing network captures in the background using Scapy."""
    
    packet_received = pyqtSignal(dict)
    capture_error = pyqtSignal(str)
    
    def __init__(self, analyzer):
        """Initialize the capture thread."""
        super().__init__()
        self.analyzer = analyzer
        self._is_running = True
        self.sniffer = None
        
        # Set the packet callback
        self.analyzer.set_packet_callback(self._packet_callback)
    
    def _packet_callback(self, packet):
        """Callback for when a packet is captured."""
        if not self._is_running or not self.analyzer.capture_active.is_set():
            logger.debug("Capture not active, ignoring packet")
            return
            
        # Process the packet and emit it
        try:
            logger.debug(f"Packet received: {repr(packet)[:200]}...")
            # Create a dictionary with packet info
            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'source': '',
                'destination': '',
                'protocol': 'Unknown',
                'length': len(packet) if hasattr(packet, '__len__') else 0,
                'info': packet.summary() if hasattr(packet, 'summary') else str(packet)[:100],
                'raw': packet
            }
            
            # Extract network layer info
            if packet.haslayer('IP'):
                ip = packet['IP']
                packet_info['source'] = ip.src
                packet_info['destination'] = ip.dst
                
                if packet.haslayer('TCP'):
                    tcp = packet['TCP']
                    packet_info['protocol'] = 'TCP'
                    packet_info['source'] += f":{tcp.sport}"
                    packet_info['destination'] += f":{tcp.dport}"
                    packet_info['info'] = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} [{tcp.flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
                elif packet.haslayer('UDP'):
                    udp = packet['UDP']
                    packet_info['protocol'] = 'UDP'
                    packet_info['source'] += f":{udp.sport}"
                    packet_info['destination'] += f":{udp.dport}"
                    packet_info['info'] = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} Len={len(udp.payload) if hasattr(udp, 'payload') else 0}"
                elif packet.haslayer('ICMP'):
                    packet_info['protocol'] = 'ICMP'
                    packet_info['info'] = f"{ip.src} -> {ip.dst} ICMP Type: {packet['ICMP'].type}"
                else:
                    packet_info['protocol'] = ip.proto
                    packet_info['info'] = f"{ip.src} -> {ip.dst} Proto: {ip.proto}"
            elif packet.haslayer('ARP'):
                arp = packet['ARP']
                packet_info['protocol'] = 'ARP'
                packet_info['source'] = arp.psrc
                packet_info['destination'] = arp.pdst
                packet_info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
            
            # Emit the processed packet using a queued connection to ensure thread safety
            QMetaObject.invokeMethod(
                self.parent(),
                "add_packet_safe",
                Qt.ConnectionType.QueuedConnection,
                Q_ARG(dict, packet_info)
            )
            
        except Exception as e:
            logger.error(f"Error processing packet in callback: {e}")
    
    def run(self):
        """Run the capture loop."""
        if not SCAPY_AVAILABLE:
            error_msg = "Scapy is not available. Please install with: pip install scapy"
            logger.error(error_msg)
            self.capture_error.emit(error_msg)
            return
            
        try:
            logger.info(f"Starting sniffer on interface: {self.analyzer.interface}")
            logger.info(f"Using filter: {self.analyzer.capture_filter}")
            
            # Verify interface exists and is up
            if not self.analyzer.interface:
                error_msg = "No network interface selected"
                logger.error(error_msg)
                self.capture_error.emit(error_msg)
                return
                
            # Start sniffing in a separate thread
            logger.debug("Creating AsyncSniffer instance...")
            try:
                self.sniffer = AsyncSniffer(
                    iface=self.analyzer.interface,
                    filter=self.analyzer.capture_filter or None,
                    prn=self._packet_callback,
                    store=0
                )
                logger.debug("AsyncSniffer instance created")
            except Exception as e:
                error_msg = f"Failed to create sniffer: {str(e)}"
                logger.error(error_msg)
                self.capture_error.emit(error_msg)
                return
            
            try:
                logger.info("Starting sniffer thread...")
                self.sniffer.start()
                
                # Small delay to ensure sniffer has started
                time.sleep(0.5)
                
                if not hasattr(self.sniffer, 'running') or not self.sniffer.running:
                    raise RuntimeError("Sniffer failed to start properly")
                    
                logger.info("Sniffer thread started successfully")
                
                # Keep the thread alive while capturing
                while self._is_running and self.analyzer.capture_active.is_set():
                    time.sleep(0.1)
                    
                logger.info("Exiting capture thread")
                
            except Exception as e:
                error_msg = f"Error in sniffer thread: {str(e)}"
                logger.exception(error_msg)
                self.capture_error.emit(error_msg)
                
        except Exception as e:
            error_msg = f"Unexpected error in capture thread: {str(e)}"
            logger.exception(error_msg)
            self.capture_error.emit(error_msg)
        finally:
            if hasattr(self, 'sniffer') and self.sniffer:
                try:
                    logger.info("Stopping sniffer...")
                    self.sniffer.stop()
                    logger.info("Sniffer stopped")
                except Exception as e:
                    logger.error(f"Error stopping sniffer: {e}")
    
    def stop(self):
        """Stop the capture thread."""
        self._is_running = False
        
        # Clear the capture active flag
        if hasattr(self.analyzer, 'capture_active'):
            self.analyzer.capture_active.clear()
        
        # Give the capture loop a moment to notice the stop request
        time.sleep(0.1)
        
        if hasattr(self, 'sniffer') and self.sniffer is not None:
            try:
                # Check if sniffer is still running
                if hasattr(self.sniffer, 'running') and self.sniffer.running:
                    logger.debug("Stopping sniffer...")
                    try:
                        # Try the standard stop method first
                        self.sniffer.stop()
                    except Exception as e:
                        logger.warning(f"Standard stop failed: {e}")
                        # If standard stop fails, try to close the socket directly
                        if hasattr(self.sniffer, 'run_socket') and self.sniffer.run_socket:
                            try:
                                self.sniffer.run_socket.close()
                            except Exception as e2:
                                logger.warning(f"Could not close socket: {e2}")
                    
                    # Additional check to ensure sniffer is stopped
                    if hasattr(self.sniffer, 'running') and self.sniffer.running:
                        logger.warning("Sniffer still running after stop attempt")
                    else:
                        logger.debug("Sniffer stopped successfully")
                else:
                    logger.debug("Sniffer was not running")
                    
            except Exception as e:
                logger.error(f"Error in sniffer stop sequence: {e}")
        
        # Wait for the thread to finish
        self.wait()


class NetworkAnalysisGUI(QMainWindow):
    """GUI for the Network Analysis tool."""
    
    def __init__(self, parent=None):
        """Initialize the Network Analysis GUI."""
        super().__init__(parent)
        
        # Set up the main window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
        """)
        self.analyzer = NetworkAnalyzer()
        self.capture_thread = None
        self.init_ui()
        self.apply_styles()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.main_layout = QVBoxLayout()
        
        # Toolbar with a subtle background
        toolbar_container = QWidget()
        toolbar_container.setObjectName("toolbarContainer")
        toolbar_container.setStyleSheet("""
            #toolbarContainer {
                background-color: #181825;
                border-bottom: 1px solid #45475a;
                padding: 8px 15px;
                border-radius: 4px;
                margin-bottom: 10px;
            }
        """)
        toolbar_layout = QVBoxLayout(toolbar_container)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        
        # Main toolbar row
        top_toolbar = QWidget()
        top_toolbar_layout = QHBoxLayout(top_toolbar)
        top_toolbar_layout.setContentsMargins(0, 0, 0, 0)
        
        # Interface selection
        interface_label = QLabel("Interface:")
        interface_label.setStyleSheet("color: #a6adc8;")
        
        self.interface_combo = QComboBox()
        self.interface_combo.setFixedWidth(200)
        self.interface_combo.setStyleSheet("""
            QComboBox {
                padding: 5px;
                border: 1px solid #45475a;
                border-radius: 4px;
                min-width: 180px;
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                width: 0;
                height: 0;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #cdd6f4;
            }
            QComboBox QAbstractItemView {
                background-color: #1e1e2e;
                color: #cdd6f4;
                selection-background-color: #89b4fa;
                selection-color: #1e1e2e;
                border: 1px solid #45475a;
                padding: 5px;
            }
        """)
        
        # Populate interfaces
        self.refresh_interfaces()
        
        # Refresh button
        refresh_btn = QPushButton("")
        refresh_btn.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        refresh_btn.setToolTip("Refresh interfaces")
        refresh_btn.setFixedSize(24, 24)
        refresh_btn.clicked.connect(self.refresh_interfaces)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #45475a;
                border-radius: 4px;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #45475a;
            }
        """)
        
        # Add to layout
        top_toolbar_layout.addWidget(interface_label)
        top_toolbar_layout.addWidget(self.interface_combo)
        top_toolbar_layout.addWidget(refresh_btn)
        top_toolbar_layout.addStretch()
        
        # Filter and controls row
        controls_toolbar = QWidget()
        controls_layout = QHBoxLayout(controls_toolbar)
        controls_layout.setContentsMargins(0, 5, 0, 0)
        
        # Add other controls (filter, buttons) here
        toolbar = self.create_toolbar()
        controls_layout.addWidget(toolbar)
        
        # Add to main toolbar
        toolbar_layout.addWidget(top_toolbar)
        toolbar_layout.addWidget(controls_toolbar)
        
        self.main_layout.addWidget(toolbar_container)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Packet list
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)  # Fixed column count to match headers
        self.packet_table.setHorizontalHeaderLabels([
            'No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'
        ])
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.setSectionsMovable(True)
        
        # Set initial column widths
        self.packet_table.setColumnWidth(0, 50)   # No.
        self.packet_table.setColumnWidth(1, 120)  # Time
        self.packet_table.setColumnWidth(2, 150)  # Source
        self.packet_table.setColumnWidth(3, 150)  # Destination
        self.packet_table.setColumnWidth(4, 80)   # Protocol
        self.packet_table.setColumnWidth(5, 70)   # Length
        
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSortingEnabled(True)
        self.packet_table.doubleClicked.connect(self.show_packet_details)
        
        # Packet details
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        
        # Add widgets to splitter
        splitter.addWidget(self.packet_table)
        splitter.addWidget(self.packet_details)
        splitter.setSizes([400, 200])
        
        # Stats panel
        stats_group = self.create_stats_panel()
        
        # Add widgets to main layout
        self.main_layout.addWidget(splitter, 1)
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.main_layout)
        self.setCentralWidget(self.central_widget)
    
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces."""
        current = self.interface_combo.currentText()
        self.interface_combo.clear()
        
        interfaces = self.analyzer.get_available_interfaces()
        for iface in interfaces:
            self.interface_combo.addItem(iface, iface)
        
        # Try to restore selection
        index = self.interface_combo.findText(current)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        elif interfaces:
            # Select the default interface if available
            default_iface = self.analyzer._get_default_interface()
            index = self.interface_combo.findText(default_iface)
            if index >= 0:
                self.interface_combo.setCurrentIndex(index)
    
    def create_toolbar(self) -> QWidget:
        """Create the toolbar with capture controls."""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Add a stretch to push everything to the right
        layout.addStretch()
        
        # Capture filter
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #a6adc8;")
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp port 80 or udp port 53")
        self.filter_edit.setMinimumWidth(300)
        self.filter_edit.setStyleSheet("""
            QLineEdit {
                padding: 5px 10px;
                border: 1px solid #45475a;
                border-radius: 4px;
                background-color: #1e1e2e;
                color: #cdd6f4;
            }
            QLineEdit:focus {
                border: 1px solid #89b4fa;
            }
        """)
        
        # Buttons
        self.start_button = QPushButton(" Start Capture")
        self.start_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaPlay))
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #a6e3a1;
                color: #1e1e2e;
                font-weight: bold;
                padding: 6px 15px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #94e2d5;
            }
            QPushButton:pressed {
                background-color: #89b4fa;
            }
        """)
        self.start_button.clicked.connect(self.start_capture)
        
        self.stop_button = QPushButton(" Stop")
        self.stop_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MediaStop))
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #f38ba8;
                color: #1e1e2e;
                font-weight: bold;
                padding: 6px 15px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #f5c2e7;
            }
            QPushButton:pressed {
                background-color: #f5e0dc;
            }
            QPushButton:disabled {
                background-color: #45475a;
                color: #6c7086;
            }
        """)
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        
        # Add widgets to layout with some spacing
        layout.addWidget(filter_label)
        layout.addWidget(self.filter_edit)
        layout.addSpacing(15)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addStretch()
        
        toolbar.setLayout(layout)
        return toolbar
    
    def create_stats_panel(self) -> QGroupBox:
        """Create the statistics panel."""
        stats_group = QGroupBox("Capture Statistics")
        layout = QHBoxLayout()
        layout.setSpacing(20)
        
        # Stats widgets with icons and better styling
        def create_stat_widget(icon, title, initial_value="0"):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.setContentsMargins(10, 5, 10, 5)
            
            # Icon and title
            title_layout = QHBoxLayout()
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 14px;")
            title_label = QLabel(title)
            title_label.setStyleSheet("color: #a6adc8; font-size: 11px;")
            title_layout.addWidget(icon_label)
            title_layout.addWidget(title_label)
            title_layout.addStretch()
            
            # Value
            value_label = QLabel(initial_value)
            value_label.setStyleSheet("""
                font-size: 18px;
                font-weight: bold;
                color: #cdd6f4;
            """)
            
            layout.addLayout(title_layout)
            layout.addWidget(value_label)
            return widget, value_label
        
        # Create stat widgets
        self.packet_widget, self.packet_count_label = create_stat_widget("📦", "Total Packets", "0")
        self.tcp_widget, self.tcp_count_label = create_stat_widget("🔗", "TCP", "0")
        self.udp_widget, self.udp_count_label = create_stat_widget("📡", "UDP", "0")
        self.other_widget, self.other_count_label = create_stat_widget("❓", "Other", "0")
        
        # Add a vertical separator
        def create_separator():
            line = QFrame()
            line.setFrameShape(QFrame.Shape.VLine)
            line.setFrameShadow(QFrame.Shadow.Sunken)
            line.setStyleSheet("color: #45475a;")
            return line
        
        # Add widgets to layout
        layout.addWidget(self.packet_widget)
        layout.addWidget(create_separator())
        layout.addWidget(self.tcp_widget)
        layout.addWidget(create_separator())
        layout.addWidget(self.udp_widget)
        layout.addWidget(create_separator())
        layout.addWidget(self.other_widget)
        layout.addStretch()
        
        stats_group.setLayout(layout)
        return stats_group
    
    def apply_styles(self):
        """Apply consistent styling to the UI."""
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
                color: #cdd6f4;
                background-color: #1e1e2e;
            }
            QTableWidget {
                background-color: #181825;
                border: 1px solid #45475a;
                gridline-color: #313244;
                color: #cdd6f4;
                selection-background-color: #89b4fa;
                selection-color: #1e1e2e;
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 4px 8px;
                border-bottom: 1px solid #313244;
            }
            QTableWidget::item:selected {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #cdd6f4;
                padding: 8px;
                border: none;
                border-right: 1px solid #45475a;
                border-bottom: 2px solid #89b4fa;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #181825;
                border: 1px solid #45475a;
                padding: 8px;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
                color: #cdd6f4;
                border-radius: 4px;
                selection-background-color: #89b4fa;
                selection-color: #1e1e2e;
            }
            QPushButton {
                padding: 6px 12px;
                border: 1px solid #45475a;
                border-radius: 4px;
                background-color: #313244;
                color: #cdd6f4;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #45475a;
                border-color: #89b4fa;
            }
            QPushButton:pressed {
                background-color: #89b4fa;
                color: #1e1e2e;
            }
            QPushButton:disabled {
                color: #6c7086;
                background-color: #24273a;
                border-color: #313244;
            }
            QLineEdit, QComboBox {
                padding: 6px 8px;
                border: 1px solid #45475a;
                border-radius: 4px;
                background-color: #181825;
                color: #cdd6f4;
                selection-background-color: #89b4fa;
                selection-color: #1e1e2e;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 10px;
            }
            QComboBox::down-arrow {
                image: url(none);
                width: 0;
                height: 0;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #cdd6f4;
            }
            QLabel {
                color: #cdd6f4;
            }
            QGroupBox {
                border: 1px solid #45475a;
                border-radius: 6px;
                margin-top: 10px;
                padding: 12px 15px 15px 15px;
                background-color: #181825;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                top: -8px;
                padding: 0 5px;
                color: #89b4fa;
                font-weight: bold;
            }
        """)
    
    def start_capture(self):
        """Start capturing network traffic."""
        # Get capture parameters
        interface = self.interface_combo.currentText()
        capture_filter = self.filter_edit.text()
        
        if not interface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface")
            return
            
        try:
            # Configure analyzer
            self.analyzer.set_interface(interface)
            self.analyzer.set_capture_filter(capture_filter)
            
            # Clear previous capture
            self.packet_table.setRowCount(0)
            self.packet_details.clear()
            
            # Start capture
            if self.analyzer.start_capture():
                self.start_button.setEnabled(False)
                self.interface_combo.setEnabled(False)
                self.stop_button.setEnabled(True)
                
                # Start capture thread
                self.capture_thread = CaptureThread(self.analyzer)
                self.capture_thread.packet_received.connect(self.add_packet)
                self.capture_thread.capture_error.connect(self.on_capture_error)
                self.capture_thread.finished.connect(self.on_capture_finished)
                self.capture_thread.start()
                
                # Update status
                self.statusBar().showMessage(f"Capturing on {interface}...")
                
        except Exception as e:
            logger.error(f"Error starting capture: {e}")
            QMessageBox.critical(self, "Capture Error", f"Failed to start capture: {str(e)}")
            self.analyzer.stop_capture()
    
    def on_capture_finished(self):
        """Handle capture thread finishing."""
        self.start_button.setEnabled(True)
        self.interface_combo.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage("Capture stopped")
    
    def stop_capture(self):
        """Stop the current capture."""
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None
        
        self.analyzer.stop_capture()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    @pyqtSlot(dict)
    def add_packet_safe(self, packet: Dict[str, Any]):
        """Thread-safe method to add a packet to the UI from any thread."""
        try:
            # This method is called via invokeMethod, so it runs in the main thread
            self.add_packet(packet)
        except Exception as e:
            logger.error(f"Error in thread-safe packet addition: {e}")
    
    def add_packet(self, packet: Dict[str, Any]):
        """Add a packet to the packet list.
        
        This method must only be called from the main thread.
        """
        try:
            if not hasattr(self, 'packet_table') or self.packet_table is None:
                logger.warning("Packet table not available, dropping packet")
                return
                
            logger.debug(f"Adding packet to UI: {packet.get('source')} -> {packet.get('destination')} {packet.get('protocol')}")
            
            # Store the current scroll position
            scrollbar = self.packet_table.verticalScrollBar()
            was_at_bottom = scrollbar.value() == scrollbar.maximum()
            
            # Add the new row
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            # Add packet data to table
            self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
            self.packet_table.setItem(row, 1, QTableWidgetItem(packet.get('timestamp', '')))
            self.packet_table.setItem(row, 2, QTableWidgetItem(packet.get('source', '')))
            self.packet_table.setItem(row, 3, QTableWidgetItem(packet.get('destination', '')))
            self.packet_table.setItem(row, 4, QTableWidgetItem(packet.get('protocol', '')))
            self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet.get('length', 0))))
            self.packet_table.setItem(row, 6, QTableWidgetItem(packet.get('info', '')))
            
            # Only scroll to bottom if we were already at the bottom
            if was_at_bottom:
                self.packet_table.scrollToBottom()
            
            # Update stats
            self.update_stats()
            
        except Exception as e:
            logger.error(f"Error adding packet to UI: {e}", exc_info=True)
    
    def update_stats(self):
        """Update the statistics display."""
        stats = self.analyzer.get_capture_stats()
        self.packet_count_label.setText(f"Packets: {stats['total_packets']}")
        self.tcp_count_label.setText(f"TCP: {stats['tcp_packets']}")
        self.udp_count_label.setText(f"UDP: {stats['udp_packets']}")
        self.other_count_label.setText(f"Other: {stats['other_packets']}")
    
    def show_packet_details(self, index):
        """Show detailed information about the selected packet."""
        row = index.row()
        if 0 <= row < self.packet_table.rowCount():
            # In a real implementation, this would show detailed packet information
            packet_num = self.packet_table.item(row, 0).text()
            protocol = self.packet_table.item(row, 4).text()
            
            details = f"""Packet #{packet_num} - {protocol}
{'='*50}
"""
            details += f"Source: {self.packet_table.item(row, 2).text()}\n"
            details += f"Destination: {self.packet_table.item(row, 3).text()}\n"
            details += f"Length: {self.packet_table.item(row, 5).text()} bytes\n"
            details += f"Timestamp: {self.packet_table.item(row, 1).text()}\n\n"
            details += "Packet details would be shown here in a real implementation.\n"
            details += "This could include protocol headers, payload, and other metadata."
            
            self.packet_details.setPlainText(details)
    
    def on_capture_error(self, error_message: str):
        """Handle capture errors."""
        QMessageBox.critical(self, "Capture Error", f"An error occurred during capture:\n{error_message}")
        self.stop_capture()
    
    def closeEvent(self, event):
        """Handle window close event."""
        self.stop_capture()
        event.accept()


def main():
    """Main function to run the Network Analysis tool as a standalone application."""
    import sys
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = QMainWindow()
    window.setWindowTitle("Hack Attack - Network Analysis")
    window.setMinimumSize(1000, 700)
    
    network_analysis = NetworkAnalysisGUI()
    window.setCentralWidget(network_analysis)
    
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
