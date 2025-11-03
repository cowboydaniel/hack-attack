#!/usr/bin/env python3
"""
Hack Attack - Professional Security Testing Suite

This is the main entry point for the Hack Attack GUI application.
"""

import sys
import os
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def is_running_as_root() -> bool:
    """Check if the script is running with root privileges."""
    return os.geteuid() == 0

def restart_with_pkexec():
    """Restart the script with pkexec for elevated privileges."""
    try:
        script_path = os.path.abspath(__file__)
        cmd = ['pkexec', sys.executable, script_path] + sys.argv[1:]
        
        # Set up environment variables to preserve GUI settings
        env = os.environ.copy()
        env['DISPLAY'] = os.environ.get('DISPLAY', ':0')
        env['XAUTHORITY'] = os.environ.get('XAUTHORITY', str(Path.home() / '.Xauthority'))
        env['DBUS_SESSION_BUS_ADDRESS'] = os.environ.get('DBUS_SESSION_BUS_ADDRESS', '')
        
        logger.info("Restarting with elevated privileges...")
        os.execvpe('pkexec', cmd, env)
        
    except Exception as e:
        logger.error(f"Failed to restart with pkexec: {e}")
        sys.exit(1)

def main():
    # Check if we need root privileges
    if not is_running_as_root():
        restart_with_pkexec()
        return
    
    # Now we have root privileges, import and start the application
    from PyQt6.QtWidgets import QApplication
    from hack_attack_gui import HackAttackGUI
    
    try:
        # Set up the application
        app = QApplication(sys.argv)
        
        # Set application style (optional dark theme)
        app.setStyle('Fusion')
        
        # Create and show the main window
        window = HackAttackGUI()
        window.show()
        
        # Start the application event loop
        sys.exit(app.exec())
        
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    # Add the current directory to the path
    if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    main()
