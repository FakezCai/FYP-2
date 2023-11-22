import psutil
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import messagebox, simpledialog
from PIL import Image, ImageTk
import os

QUARANTINE_FILE = "quarantined_threats.txt"

class KeyloggerDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection")
        self.root.geometry("400x400")
        self.root.resizable(False, False)
        self.potential_threats = []

        img = Image.open("img/start.png")
        img = img.resize((200, 160), Image.ANTIALIAS)
        img = ImageTk.PhotoImage(img)

        img_label = tk.Label(root, image=img, borderwidth=0)
        img_label.image = img

        img_label.pack(expand=True)
        self.start_button = img_label
        self.start_button.bind("<Button-1>", self.start_detection_event)

        self.status_label = tk.Label(root, text="Click 'Start Detection' to begin.", font=("Arial", 12))
        self.status_label.pack(pady=10)

    def check_for_keylogger(self):
        potential_threats = []

        processes = psutil.process_iter(attrs=['pid', 'name', 'cmdline'])

        keylogger_keywords = ["keylogger", "logger", "keylog", "keystroke", "keycapture"]

        # Load quarantined threats from the file
        quarantined_threats = set()
        if os.path.exists(QUARANTINE_FILE):
            with open(QUARANTINE_FILE, "r") as file:
                quarantined_threats = set(file.read().splitlines())

        for process in processes:
            process_name = process.info['name'].lower()
            cmdline = " ".join(process.info['cmdline']).lower() if process.info['cmdline'] else ""

            if any(keyword in process_name or keyword in cmdline for keyword in keylogger_keywords):
                if process.info['pid'] not in quarantined_threats:
                    potential_threats.append(process)

        return potential_threats

    def start_detection(self):
        self.start_button.config(state=tk.DISABLED)  # Disable the button during detection
        self.status_label.config(text="Detecting keyloggers... Please wait.")
        self.root.update()  # Force an update to show the status message

        self.potential_threats = self.check_for_keylogger()
        if self.potential_threats:
            self.alert_user_about_threats()
        else:
            self.monitor_file_changes()
            self.generate_report(self.potential_threats)
            messagebox.showinfo("No Threats Detected", "No potential threats detected. File system monitoring started.")

        self.status_label.config(text="Click 'Start Detection' to begin.")  # Reset status message
        self.start_button.config(state=tk.NORMAL)  # Re-enable the button

    def start_detection_event(self, event):
        self.start_detection()

    def alert_user_about_threats(self):
        for threat in self.potential_threats:
            threat_pid = threat.info['pid']
            threat_name = threat.info['name']
            threat_cmdline = " ".join(threat.info['cmdline']) if threat.info['cmdline'] else "N/A"

            user_choice = messagebox.askquestion(
                "Potential Keylogger Threat Detected",
                f"PID: {threat_pid}\nName: {threat_name}\nCommand Line: {threat_cmdline}\n"
                "Do you want to take any action on this threat?",
            )

            if user_choice == 'yes':
                self.remove_threat(threat_pid)
            elif user_choice == 'no':
                self.rename_threat(threat_pid, threat_name)

    def remove_threat(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate()
        except psutil.NoSuchProcess:
            pass

    def rename_threat(self, pid, name):
        new_name = simpledialog.askstring("Rename Threat", f"Enter a new name for the threat (PID: {pid}):", initialvalue=name)
        if new_name:
            for threat in self.potential_threats:
                if threat.info['pid'] == pid:
                    original_name = threat.info['name']
                    threat.info['name'] = new_name
                    action = f"Renamed from {original_name} to {new_name}"
                    self.save_action_to_report(pid, original_name, action)
                    break

    def monitor_file_changes(self):
        event_handler = FileChangeHandler()
        observer = Observer()
        observer.schedule(event_handler, path=".", recursive=True)
        observer.start()

    def generate_report(self, threats):
        current_datetime = datetime.datetime.now()
        report_filename = "keylogger_report.txt"

        with open(report_filename, "a") as report_file:
            report_file.write(f"Report generated on: {current_datetime}\n")
            if threats:
                report_file.write("Potential Keylogger Threats:\n\n")
                for threat in threats:
                    report_file.write(f"PID: {threat.info['pid']}\n")
                    report_file.write(f"Name: {threat.info['name']}\n")
                    report_file.write(f"Command Line: {' '.join(threat.info['cmdline'])}\n")
                    report_file.write("=" * 40 + "\n")
            else:
                report_file.write("No potential threats detected.\n")
            report_file.write("=" * 60 + "\n\n")

    def save_action_to_report(self, pid, name, action):
        current_datetime = datetime.datetime.now()
        report_filename = "keylogger_report.txt"

        with open(report_filename, "a") as report_file:
            report_file.write(f"Action taken on {current_datetime} for PID {pid} (Name: {name}): {action}\n")

class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        print(f"File modified: {event.src_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectionApp(root)
    root.mainloop()