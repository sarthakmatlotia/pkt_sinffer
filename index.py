import tkinter as tk
from scapy.all import sniff, IP, TCP
import threading

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("600x400")

# Create a Text widget to display the captured data
packet_display = tk.Text(root, height=20, width=80)
packet_display.pack(padx=10, pady=10)

# Callback function to handle the packet data
def packet_callback(packet):
    display_text = ""

    if packet.haslayer(IP):  # Check if the packet has an IP layer
        display_text += f"Source IP: {packet[IP].src}\n"
        display_text += f"Destination IP: {packet[IP].dst}\n"
    
    if packet.haslayer(TCP):  # Check if the packet has a TCP layer
        display_text += f"Source Port: {packet[TCP].sport}\n"
        display_text += f"Destination Port: {packet[TCP].dport}\n"
    
    display_text += "\n"

    # Insert the packet data into the Text widget
    packet_display.insert(tk.END, display_text)
    packet_display.yview(tk.END)  # Scroll to the bottom

    # Log the packet data to a file
    with open("packet_log.txt", "a") as log_file:
        log_file.write(display_text)

# Function to start sniffing in a separate thread to avoid blocking the GUI
def start_sniffing():
    sniff(prn=packet_callback, store=0, filter="tcp", count=0)

# Function to run sniffing in a separate thread
def sniff_thread():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

# Button to start sniffing
start_button = tk.Button(root, text="Start Sniffing", command=sniff_thread)
start_button.pack(pady=10)

# Button to clear the packet display
def clear_display():
    packet_display.delete(1.0, tk.END)

clear_button = tk.Button(root, text="Clear Display", command=clear_display)
clear_button.pack(pady=10)

# Run the GUI
root.mainloop()