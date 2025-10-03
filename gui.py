import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import sys
import os
import json
from datetime import datetime
from zoneinfo import available_timezones

# This ensures that we can find main.py, regardless of where the script is run from.
# It adds the script's own directory to the Python's search path.
project_dir = os.path.dirname(os.path.abspath(__file__))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

def log_error_to_file(error_message: str):
    """Appends an error message with a timestamp to the log file."""
    log_file_path = os.path.join(os.path.expanduser("~"), ".media_tool_gui.log")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(f"--- {timestamp} ---\n")
            f.write(error_message)
            f.write("\n\n")
    except IOError as e:
        # If we can't even write to the log file, print to stderr as a last resort.
        print(f"FATAL: Could not write to log file {log_file_path}: {e}", file=sys.stderr)

# Import the functions from your command-line tool
try:
    from main import rename_media, process_duplicate_files, flatten_directory
except ImportError:
    import traceback
    tb_str = traceback.format_exc()
    log_error_to_file(tb_str)
    error_msg = f"A critical error occurred on startup: See log file"
    messagebox.showerror("Fatal Import Error", error_msg)
    sys.exit(1)

class QueueWriter:
    """A file-like object to redirect stdout/stderr to a queue."""
    def __init__(self, queue_instance):
        self.queue = queue_instance

    def write(self, text):
        self.queue.put(text)

    def flush(self):
        pass

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Media Organization Tool")
        self.geometry("800x600")

        self.config_file = os.path.join(os.path.expanduser("~"), ".media_tool_gui.json")
        self.queue = queue.Queue()
        self.thread = None

        self.create_widgets()
        self.load_settings()
        self.process_queue()
        self.update_command_preview()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # Frame for controls
        control_frame = ttk.Frame(self, padding="10")
        control_frame.pack(fill=tk.X, side=tk.TOP)

        # --- Folder Path ---
        ttk.Label(control_frame, text="Folder Path:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.folder_path_var = tk.StringVar()
        self.folder_path_var.trace_add("write", self.update_command_preview)
        self.folder_path_entry = ttk.Entry(control_frame, textvariable=self.folder_path_var, width=60)
        self.folder_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.browse_button = ttk.Button(control_frame, text="Browse...", command=self.browse_folder)
        self.browse_button.grid(row=0, column=2, sticky=tk.W, padx=5)
        control_frame.grid_columnconfigure(1, weight=1)

        # --- Actions ---
        actions_frame = ttk.LabelFrame(self, text="Actions", padding="10")
        actions_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)

        self.flatten_var = tk.BooleanVar()
        ttk.Checkbutton(actions_frame, text="Flatten directory structure", variable=self.flatten_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.delete_dups_var = tk.BooleanVar()
        ttk.Checkbutton(actions_frame, text="Delete duplicate files", variable=self.delete_dups_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.rename_var = tk.BooleanVar()
        ttk.Checkbutton(actions_frame, text="Rename media files", variable=self.rename_var, command=self.update_command_preview).pack(anchor=tk.W)

        # --- Settings ---
        settings_frame = ttk.LabelFrame(self, text="Settings", padding="10")
        settings_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)

        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Dry Run (preview changes without modifying files)", variable=self.dry_run_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.debug_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Debug (verbose output)", variable=self.debug_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.force_overwrite_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="Force Overwrite (replace existing timestamp prefixes)", variable=self.force_overwrite_var, command=self.update_command_preview).pack(anchor=tk.W)

        # --- Timezone Selector ---
        ttk.Label(settings_frame, text="Timezone (for renaming files without any time zone info):").pack(anchor=tk.W, pady=(10, 0))
        self.timezone_var = tk.StringVar()
        self.timezone_var.trace_add("write", self.update_command_preview)
        # Get all IANA timezones and add a blank option for 'None'
        timezones = [""] + sorted(list(available_timezones()))
        self.timezone_combo = ttk.Combobox(settings_frame, textvariable=self.timezone_var, values=timezones, state="readonly")
        self.timezone_combo.pack(anchor=tk.W, fill=tk.X, expand=True)

        # --- Command Preview ---
        command_frame = ttk.LabelFrame(self, text="Command Line Preview", padding="10")
        command_frame.pack(fill=tk.X, padx=10, pady=5)

        self.command_preview_var = tk.StringVar()
        command_entry = ttk.Entry(command_frame, textvariable=self.command_preview_var, state="readonly", font=("Courier", 10))
        command_entry.pack(fill=tk.X, expand=True, ipady=2)

        # --- Buttons Frame ---
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(pady=10)

        self.run_button = ttk.Button(buttons_frame, text="Run Tasks", command=self.run_tasks)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.copy_button = ttk.Button(buttons_frame, text="Copy Output", command=self.copy_output_to_clipboard)
        self.copy_button.pack(side=tk.LEFT, padx=5)

        # --- Output Console ---
        console_frame = ttk.LabelFrame(self, text="Output", padding="10")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.console = tk.Text(console_frame, wrap=tk.WORD, height=15)
        # Make the text widget read-only by intercepting key presses.
        # This allows selection with the mouse and right-click copy, but not modification.
        self.console.bind("<KeyPress>", lambda e: "break")
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(console_frame, command=self.console.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.config(yscrollcommand=scrollbar.set)
        
    def browse_folder(self):
        initial_dir = self.folder_path_var.get()
        if not initial_dir or not os.path.isdir(initial_dir):
            initial_dir = os.path.expanduser("~")

        folder_selected = filedialog.askdirectory(initialdir=initial_dir)
        if folder_selected:
            self.folder_path_var.set(os.path.abspath(folder_selected))

    def load_settings(self):
        """Loads the last used folder path from the config file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    last_path = config.get("last_folder_path")
                    if last_path and os.path.isdir(last_path):
                        self.folder_path_var.set(last_path)
                    last_timezone = config.get("last_timezone")
                    if last_timezone:
                        self.timezone_var.set(last_timezone)
        except (IOError, json.JSONDecodeError) as e:
            # It's okay if this fails, we just won't load previous settings.
            print(f"Could not load settings from {self.config_file}: {e}")

    def save_settings(self):
        """Saves the current folder path to the config file."""
        config = {
            "last_folder_path": self.folder_path_var.get(),
            "last_timezone": self.timezone_var.get()
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except IOError as e:
            print(f"Could not save settings to {self.config_file}: {e}")

    def copy_output_to_clipboard(self):
        """Copies the content of the output console to the clipboard."""
        try:
            self.clipboard_clear()
            self.clipboard_append(self.console.get("1.0", tk.END))
        except tk.TclError:
            messagebox.showwarning("Clipboard Error", "Could not access the clipboard.")

    def update_command_preview(self, *args):
        """Builds and displays the equivalent command-line command."""
        parts = ["python", "main.py"]
        
        folder_path = self.folder_path_var.get()
        if folder_path:
            # Use quotes to handle paths with spaces
            parts.append(f'"{folder_path}"')
        else:
            parts.append("<folder_path>")

        if self.flatten_var.get(): parts.append("--flatten")
        if self.delete_dups_var.get(): parts.append("--delete-dups")
        if self.rename_var.get(): parts.append("--rename")
        if self.dry_run_var.get(): parts.append("--dry-run")
        if self.debug_var.get(): parts.append("--debug")
        if self.force_overwrite_var.get(): parts.append("--force-overwrite")
        timezone = self.timezone_var.get()
        if timezone:
            parts.append(f'--timezone "{timezone}"')
            
        self.command_preview_var.set(" ".join(parts))

    def on_closing(self):
        """Handle the window closing event, saving settings before exit."""
        current_path = self.folder_path_var.get()
        if current_path and os.path.isdir(current_path):
            self.save_settings()
        self.destroy()

    def run_tasks(self):
        folder_path = self.folder_path_var.get()
        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        self.save_settings()

        if self.thread and self.thread.is_alive():
            messagebox.showwarning("Busy", "A task is already running.")
            return

        self.console.delete('1.0', tk.END) # Clear console
        self.run_button.config(state=tk.DISABLED, text="Running...")

        # Get settings from GUI
        params = {
            "folder_path": folder_path,
            "do_flatten": self.flatten_var.get(),
            "do_delete_dups": self.delete_dups_var.get(),
            "do_rename": self.rename_var.get(),
            "is_dry_run": self.dry_run_var.get(),
            "is_debug": self.debug_var.get(),
            "force_overwrite": self.force_overwrite_var.get(),
            "timezone": self.timezone_var.get() or None,
        }
        
        # Start worker thread
        self.thread = threading.Thread(target=self.worker_thread, args=(params,))
        self.thread.start()

    def worker_thread(self, params: dict):
        """This runs in a separate thread to avoid freezing the GUI."""
        # Redirect stdout and stderr to our queue
        writer = QueueWriter(self.queue)
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = writer
        sys.stderr = writer
        
        try:
            self.queue.put("--- Starting tasks ---\n")
            if params["do_flatten"]:
                self.queue.put("\n=== Running: Flatten Directory ===\n")
                flatten_directory(folder_path=params["folder_path"], dry_run=params["is_dry_run"])
            
            if params["do_delete_dups"]:
                self.queue.put("\n=== Running: Find/Delete Duplicates ===\n")
                process_duplicate_files(folder_path=params["folder_path"], dry_run=params["is_dry_run"], debug=params["is_debug"])

            if params["do_rename"]:
                self.queue.put("\n=== Running: Rename Media ===\n")
                rename_media(
                    folder_path=params["folder_path"],
                    dry_run=params["is_dry_run"],
                    debug=params["is_debug"],
                    force_overwrite=params["force_overwrite"],
                    timezone=params["timezone"]
                )
            
            self.queue.put("\n--- All tasks completed! ---\n")
        except Exception as e:
            self.queue.put(f"\n--- AN ERROR OCCURRED ---\n{e}\n")
            import traceback
            tb_str = traceback.format_exc()
            log_error_to_file(tb_str)
            self.queue.put(tb_str)
        finally:
            # Restore stdout and stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            # Signal the GUI thread that the work is done by putting None in the queue
            self.queue.put(None)

    def process_queue(self):
        """Check the queue for messages from the worker thread and display them."""
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg is None:  # Sentinel value indicates thread finished
                    self.run_button.config(state=tk.NORMAL, text="Run Tasks")
                    # Do not return. This allows the polling to continue for subsequent runs.
                else:
                    # Handling terminal progress bars (with '\r') can be complex in a Text widget.
                    # We strip the message and only add it if it's not empty, to avoid adding blank
                    # lines for messages that only contain whitespace or newlines.
                    clean_msg = msg.strip()
                    if clean_msg:
                        self.console.insert(tk.END, clean_msg + '\n')
                        self.console.see(tk.END)  # Scroll to the end
        except queue.Empty:
            pass # No new messages in queue
        
        # Poll the queue again after 100ms
        self.after(100, self.process_queue)

if __name__ == "__main__":
    app = App()
    app.mainloop()