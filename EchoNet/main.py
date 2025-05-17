import subprocess
import platform
import ipaddress
import socket
import csv
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


def ping_host(ip):
    system = platform.system().lower()
    param = "-n" if system == "windows" else "-c"
    if system == "windows":
        timeout_param = "-w"
        timeout = "1000"
    else:
        timeout_param = "-W"
        timeout = "1"
    command = ["ping", param, "1", timeout_param, timeout, str(ip)]
    try:
        subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def get_mac_address(ip):
    system = platform.system().lower()
    if system == "windows":
        try:
            output = subprocess.check_output(["arp", "-a", str(ip)], encoding='utf-8')
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1]
                        if "-" in mac or ":" in mac:
                            return mac
        except Exception:
            pass
    else:
        try:
            output = subprocess.check_output(["arp", "-n", str(ip)], encoding='utf-8')
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[2]
                        if mac != "(incomplete)":
                            return mac
        except Exception:
            pass
    return "N/A"


def scan_ports(ip, ports=[22, 80, 443]):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def scan_network(network_cidr, ports=[22, 80, 443]):
    network = ipaddress.ip_network(network_cidr, strict=False)
    live_hosts = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in network.hosts()}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    live_hosts.append(str(ip))
            except Exception:
                pass

    results = []
    for ip in live_hosts:
        mac = get_mac_address(ip)
        open_ports = scan_ports(ip, ports)
        results.append({
            "IP": ip,
            "MAC": mac,
            "Open Ports": ",".join(str(p) for p in open_ports) if open_ports else "None"
        })

    return results


def set_green_black_theme(root):
    style = ttk.Style(root)
    root.configure(bg="#0d0d0d")
    style.theme_use('clam')

    style.configure("TFrame", background="#0d0d0d")
    style.configure("TLabel", background="#0d0d0d", foreground="#00ff88")
    style.configure("TEntry", fieldbackground="#1a1a1a", foreground="#00ff88")
    style.configure("TButton",
                    background="#1a1a1a",
                    foreground="#00ff88",
                    borderwidth=0,
                    focusthickness=3,
                    focuscolor="#00ff88",
                    relief="flat")
    style.map("TButton",
              foreground=[("pressed", "#0d0d0d"), ("active", "#00ff88")],
              background=[("pressed", "#00ff88"), ("active", "#1a1a1a")])

    style.configure("Treeview",
                    background="#1a1a1a",
                    foreground="#00ff88",
                    fieldbackground="#0d0d0d",
                    bordercolor="#0d0d0d",
                    borderwidth=0)
    style.configure("Treeview.Heading",
                    background="#1a1a1a",
                    foreground="#00ff88",
                    relief="flat")
    style.map("Treeview.Heading",
              background=[("active", "#00aa44")])

    style.configure("Vertical.TScrollbar",
                    background="#1a1a1a",
                    troughcolor="#0d0d0d",
                    arrowcolor="#00ff88")


class EchoNet(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EchoNet")
        self.geometry("700x400")
        set_green_black_theme(self)
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(frame, text="Network CIDR (e.g. 192.168.1.0/24):").pack(side="left")
        self.subnet_entry = ttk.Entry(frame)
        self.subnet_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.subnet_entry.insert(0, "192.168.1.0/24")

        self.scan_button = ttk.Button(frame, text="Scan Network", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(0, 5))

        self.save_button = ttk.Button(frame, text="Save Results", command=self.save_results)
        self.save_button.pack(side="left")
        self.save_button["state"] = "disabled"

        self.tree = ttk.Treeview(self, columns=("IP", "MAC", "Ports"), show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Ports", text="Open Ports")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        self.status_bar.pack(fill="x")

    def start_scan(self):
        subnet = self.subnet_entry.get().strip()
        if not subnet:
            messagebox.showerror("Error", "Please enter a valid subnet")
            return

        self.status_var.set("Scanning network...")
        self.scan_button["state"] = "disabled"
        self.save_button["state"] = "disabled"
        self.tree.delete(*self.tree.get_children())

        threading.Thread(target=self.run_scan, args=(subnet,), daemon=True).start()

    def run_scan(self, subnet):
        try:
            results = scan_network(subnet)
            self.after(0, self.show_results, results)
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self.scan_finished)

    def show_results(self, results):
        for item in results:
            self.tree.insert("", "end", values=(item["IP"], item["MAC"], item["Open Ports"]))

    def scan_finished(self):
        self.status_var.set("Scan complete")
        self.scan_button["state"] = "normal"
        self.save_button["state"] = "normal"

    def save_results(self):
        if not self.tree.get_children():
            messagebox.showinfo("Info", "No results to save")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not file_path:
            return

        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "MAC Address", "Open Ports"])
            for child in self.tree.get_children():
                writer.writerow(self.tree.item(child)["values"])

        messagebox.showinfo("Success", f"Results saved to {file_path}")


def main():
    app = EchoNet()
    app.mainloop()


if __name__ == "__main__":
    main()

