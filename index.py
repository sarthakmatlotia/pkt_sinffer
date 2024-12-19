import sys
# Add the path where PyQt5 is installed (in case it's not recognized)
sys.path.append(r"C:\ProgramData\anaconda3\Lib\site-packages\PyQt5")

import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit

# Create the main window using PyQt5
class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 600, 400)

        # Create a vertical layout
        layout = QVBoxLayout()

        # Create a QTextEdit widget to display the captured data
        self.packet_display = QTextEdit(self)
        self.packet_display.setReadOnly(True)
        layout.addWidget(self.packet_display)

        # Create the start button to begin sniffing
        self.start_button = QPushButton("Start Sniffing", self)
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        # Create the clear button to clear the display
        self.clear_button = QPushButton("Clear Display", self)
        self.clear_button.clicked.connect(self.clear_display)
        layout.addWidget(self.clear_button)

        # Set the layout for the main window
        self.setLayout(layout)

        # Open the log file in append mode
        self.log_file = open("packet_log.txt", "a")

        # Initialize the packet counter
        self.packet_counter = 0

    # Callback function to handle packet data
    def packet_callback(self, packet):
        self.packet_counter += 1  # Increment the packet counter
        display_text = f"Packet #{self.packet_counter}\n"  # Show the packet serial number

        if packet.haslayer(IP):  # Check if the packet has an IP layer
            display_text += f"Source IP: {packet[IP].src}\n"
            display_text += f"Destination IP: {packet[IP].dst}\n"
        
        if packet.haslayer(TCP):  # Check if the packet has a TCP layer
            display_text += f"Source Port: {packet[TCP].sport}\n"
            display_text += f"Destination Port: {packet[TCP].dport}\n"
        
        display_text += "\n"

        # Insert the packet data into the QTextEdit widget
        self.packet_display.append(display_text)

        # Save the packet data to the log file
        self.save_log(display_text)

    # Function to save packet data to the log file
    def save_log(self, packet_data):
        self.log_file.write(packet_data)
        self.log_file.flush()  # Ensure the data is written immediately to the file

    # Function to start sniffing
    def start_sniffing(self):
        # Run sniffing in a separate thread to avoid blocking the GUI
        sniff_thread = threading.Thread(target=self.sniff)
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff(self):
        # Sniff packets and use packet_callback to display packet data
        sniff(prn=self.packet_callback, store=0, filter="tcp", count=0)

    # Function to clear the display
    def clear_display(self):
        self.packet_display.clear()

    # Close the log file when the application is closed
    def closeEvent(self, event):
        self.log_file.close()
        event.accept()

# Main function to run the application
def main():
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())

# Run the application
if __name__ == "__main__":
    main()