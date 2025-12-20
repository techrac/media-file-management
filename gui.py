import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import sys
import os
import json
from datetime import datetime
from zoneinfo import available_timezones
from version import __version__

# macOS-specific setup for Tkinter
if sys.platform == 'darwin':
    # Ensure the app can be accessed
    os.environ['PYTHONUNBUFFERED'] = '1'

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
    from main import (
        rename_media, process_duplicate_files, flatten_directory,
        connect_ssh, disconnect_ssh, scan_permission_issues, scan_empty_folders_remote,
        scan_legacy_files_remote, scan_problematic_filenames_remote,
        generate_categorized_cleanup_scripts
    )
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
        self.title(f"Media Organization Tool v{__version__}")
        self.geometry("800x600")

        self.config_file = os.path.join(os.path.expanduser("~"), ".media_tool_gui.json")
        self.queue = queue.Queue()
        self.thread = None

        self.create_widgets()
        self.load_settings()
        self.on_mode_changed()  # Initialize UI based on loaded mode
        self.process_queue()
        self.update_command_preview()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        # --- Mode Selection ---
        mode_frame = ttk.LabelFrame(self, text="Mode", padding="10")
        mode_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
        
        self.mode_var = tk.StringVar(value="local")
        self.mode_var.trace_add("write", self.on_mode_changed)
        ttk.Radiobutton(mode_frame, text="Local Mode (direct file operations)", variable=self.mode_var, value="local").pack(anchor=tk.W, padx=5)
        ttk.Radiobutton(mode_frame, text="Remote SSH Mode (generate cleanup scripts)", variable=self.mode_var, value="remote").pack(anchor=tk.W, padx=5)

        # Frame for controls
        control_frame = ttk.Frame(self, padding="10")
        control_frame.pack(fill=tk.X, side=tk.TOP)

        # --- Local Mode: Folder Path ---
        self.folder_path_frame = ttk.Frame(control_frame)
        self.folder_path_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        ttk.Label(self.folder_path_frame, text="Folder Path:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.folder_path_var = tk.StringVar()
        self.folder_path_var.trace_add("write", self.update_command_preview)
        self.folder_path_entry = ttk.Entry(self.folder_path_frame, textvariable=self.folder_path_var, width=60)
        self.folder_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.browse_button = ttk.Button(self.folder_path_frame, text="Browse...", command=self.browse_folder)
        self.browse_button.grid(row=0, column=2, sticky=tk.W, padx=5)
        self.folder_path_frame.grid_columnconfigure(1, weight=1)
        control_frame.grid_columnconfigure(0, weight=1)

        # --- Local Mode: Actions ---
        self.local_actions_frame = ttk.LabelFrame(self, text="Actions", padding="10")
        self.local_actions_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)

        self.flatten_var = tk.BooleanVar()
        ttk.Checkbutton(self.local_actions_frame, text="Flatten directory structure", variable=self.flatten_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.delete_dups_var = tk.BooleanVar()
        ttk.Checkbutton(self.local_actions_frame, text="Delete duplicate files", variable=self.delete_dups_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.rename_var = tk.BooleanVar()
        ttk.Checkbutton(self.local_actions_frame, text="Rename media files", variable=self.rename_var, command=self.update_command_preview).pack(anchor=tk.W)

        # --- Local Mode: Settings ---
        self.local_settings_frame = ttk.LabelFrame(self, text="Settings", padding="10")
        self.local_settings_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)

        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.local_settings_frame, text="Dry Run (preview changes without modifying files)", variable=self.dry_run_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.debug_var = tk.BooleanVar()
        ttk.Checkbutton(self.local_settings_frame, text="Debug (verbose output)", variable=self.debug_var, command=self.update_command_preview).pack(anchor=tk.W)

        self.force_overwrite_var = tk.BooleanVar()
        ttk.Checkbutton(self.local_settings_frame, text="Force Overwrite (replace existing timestamp prefixes)", variable=self.force_overwrite_var, command=self.update_command_preview).pack(anchor=tk.W)

        # --- Local Mode: Timezone Selector ---
        ttk.Label(self.local_settings_frame, text="Timezone (only used for files without any time zone info):").pack(anchor=tk.W, pady=(10, 0))
        self.timezone_var = tk.StringVar()
        self.timezone_var.trace_add("write", self.update_command_preview)
        # Get all IANA timezones and add a blank option for 'None'
        timezones = [""] + sorted(list(available_timezones()))
        self.timezone_combo = ttk.Combobox(self.local_settings_frame, textvariable=self.timezone_var, values=timezones, state="readonly")
        self.timezone_combo.pack(anchor=tk.W, fill=tk.X, expand=True)

        # --- Remote Mode: SSH Connection ---
        self.ssh_frame = ttk.LabelFrame(self, text="SSH Connection", padding="10")
        
        ttk.Label(self.ssh_frame, text="Host/IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ssh_host_var = tk.StringVar()
        self.ssh_host_entry = ttk.Entry(self.ssh_frame, textvariable=self.ssh_host_var, width=40)
        self.ssh_host_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.ssh_frame, text="SSH Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.ssh_user_var = tk.StringVar()
        self.ssh_user_entry = ttk.Entry(self.ssh_frame, textvariable=self.ssh_user_var, width=40)
        self.ssh_user_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.ssh_frame, text="SSH Key File:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.ssh_key_var = tk.StringVar()
        self.ssh_key_entry = ttk.Entry(self.ssh_frame, textvariable=self.ssh_key_var, width=40)
        self.ssh_key_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(self.ssh_frame, text="Browse...", command=self.browse_ssh_key).grid(row=2, column=2, sticky=tk.W, padx=5)
        
        ttk.Label(self.ssh_frame, text="SSH Port:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.ssh_port_var = tk.StringVar(value="22")
        self.ssh_port_entry = ttk.Entry(self.ssh_frame, textvariable=self.ssh_port_var, width=10)
        self.ssh_port_entry.grid(row=3, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(self.ssh_frame, text="Share Path:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.share_path_var = tk.StringVar()
        self.share_path_entry = ttk.Entry(self.ssh_frame, textvariable=self.share_path_var, width=40)
        self.share_path_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.ssh_frame, text="Share Owner:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.share_owner_var = tk.StringVar()
        self.share_owner_entry = ttk.Entry(self.ssh_frame, textvariable=self.share_owner_var, width=40)
        self.share_owner_entry.grid(row=5, column=1, sticky=(tk.W, tk.E), padx=5)
        
        self.ssh_frame.grid_columnconfigure(1, weight=1)

        # --- Remote Mode: Cleanup Options ---
        self.remote_cleanup_frame = ttk.LabelFrame(self, text="Cleanup Options", padding="10")
        
        self.cleanup_permissions_var = tk.BooleanVar()
        ttk.Checkbutton(self.remote_cleanup_frame, text="Fix permissions", variable=self.cleanup_permissions_var).pack(anchor=tk.W)
        
        self.cleanup_empty_folders_var = tk.BooleanVar()
        ttk.Checkbutton(self.remote_cleanup_frame, text="Cleanup empty folders", variable=self.cleanup_empty_folders_var).pack(anchor=tk.W)
        
        self.cleanup_legacy_files_var = tk.BooleanVar()
        ttk.Checkbutton(self.remote_cleanup_frame, text="Cleanup legacy files (Windows cache: Thumbs.db, ehthumbs.db, Desktop.ini, IconCache.db; .streams, .@__thumb, ._* resource forks)", variable=self.cleanup_legacy_files_var).pack(anchor=tk.W)
        
        self.cleanup_filenames_var = tk.BooleanVar()
        ttk.Checkbutton(self.remote_cleanup_frame, text="Cleanup problematic filenames", variable=self.cleanup_filenames_var).pack(anchor=tk.W)
        
        ttk.Label(self.remote_cleanup_frame, text="Problematic characters (replaced with _; spaces trimmed):").pack(anchor=tk.W, pady=(10, 0))
        self.problem_chars_var = tk.StringVar(value="?, ;, :, ~, !, $, /, \\")
        ttk.Entry(self.remote_cleanup_frame, textvariable=self.problem_chars_var, width=30).pack(anchor=tk.W, fill=tk.X)
        
        ttk.Label(self.remote_cleanup_frame, text="Exclude folders:").pack(anchor=tk.W, pady=(5, 0))
        self.exclude_folder_var = tk.StringVar(value=".fcpbundle")
        ttk.Entry(self.remote_cleanup_frame, textvariable=self.exclude_folder_var, width=30).pack(anchor=tk.W, fill=tk.X)

        # --- Command Preview ---
        command_frame = ttk.LabelFrame(self, text="Command Line Preview", padding="10")
        command_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        self.command_preview_var = tk.StringVar()
        command_entry = ttk.Entry(command_frame, textvariable=self.command_preview_var, state="readonly", font=("Courier", 10))
        command_entry.pack(fill=tk.X, expand=True, ipady=2)

        # --- Buttons Frame ---
        buttons_frame = ttk.Frame(self)
        buttons_frame.pack(side=tk.TOP, pady=10)

        self.run_button = ttk.Button(buttons_frame, text="Run Tasks", command=self.run_tasks)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.copy_button = ttk.Button(buttons_frame, text="Copy Output", command=self.copy_output_to_clipboard)
        self.copy_button.pack(side=tk.LEFT, padx=5)

        # --- Output Console (at bottom) ---
        console_frame = ttk.LabelFrame(self, text="Output", padding="10")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 10))

        self.console = tk.Text(console_frame, wrap=tk.WORD, height=15)
        # Make the text widget read-only by intercepting key presses.
        # This allows selection with the mouse and right-click copy, but not modification.
        self.console.bind("<KeyPress>", lambda e: "break")
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(console_frame, command=self.console.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.config(yscrollcommand=scrollbar.set)
        
    def on_mode_changed(self, *args):
        """Handle mode change - show/hide appropriate UI elements."""
        mode = self.mode_var.get()
        if mode == "local":
            self.folder_path_frame.grid()
            self.local_actions_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)
            self.local_settings_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)
            self.ssh_frame.pack_forget()
            self.remote_cleanup_frame.pack_forget()
        else:
            self.folder_path_frame.grid_remove()
            self.local_actions_frame.pack_forget()
            self.local_settings_frame.pack_forget()
            self.ssh_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)
            self.remote_cleanup_frame.pack(fill=tk.X, padx=10, pady=5, anchor=tk.W)
        self.update_command_preview()
        
    def browse_folder(self):
        initial_dir = self.folder_path_var.get()
        if not initial_dir or not os.path.isdir(initial_dir):
            initial_dir = os.path.expanduser("~")

        folder_selected = filedialog.askdirectory(initialdir=initial_dir)
        if folder_selected:
            self.folder_path_var.set(os.path.abspath(folder_selected))
    
    def browse_ssh_key(self):
        initial_file = self.ssh_key_var.get()
        if not initial_file or not os.path.exists(initial_file):
            initial_file = os.path.expanduser("~/.ssh")
        
        key_selected = filedialog.askopenfilename(
            initialdir=initial_file,
            title="Select SSH Private Key",
            filetypes=[("All Files", "*.*")]
        )
        if key_selected:
            self.ssh_key_var.set(key_selected)

    def load_settings(self):
        """Loads the last used settings from the config file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    mode = config.get("mode", "local")
                    self.mode_var.set(mode)
                    
                    last_path = config.get("last_folder_path")
                    if last_path and os.path.isdir(last_path):
                        self.folder_path_var.set(last_path)
                    last_timezone = config.get("last_timezone")
                    if last_timezone:
                        self.timezone_var.set(last_timezone)
                    
                    if config.get("ssh_host"):
                        self.ssh_host_var.set(config["ssh_host"])
                    if config.get("ssh_user"):
                        self.ssh_user_var.set(config["ssh_user"])
                    if config.get("ssh_key"):
                        self.ssh_key_var.set(config["ssh_key"])
                    if config.get("ssh_port"):
                        self.ssh_port_var.set(config["ssh_port"])
                    if config.get("share_path"):
                        self.share_path_var.set(config["share_path"])
                    if config.get("share_owner"):
                        self.share_owner_var.set(config["share_owner"])
        except (IOError, json.JSONDecodeError) as e:
            # It's okay if this fails, we just won't load previous settings.
            print(f"Could not load settings from {self.config_file}: {e}")

    def save_settings(self):
        """Saves the current settings to the config file."""
        config = {
            "mode": self.mode_var.get(),
            "last_folder_path": self.folder_path_var.get(),
            "last_timezone": self.timezone_var.get(),
            "ssh_host": self.ssh_host_var.get(),
            "ssh_user": self.ssh_user_var.get(),
            "ssh_key": self.ssh_key_var.get(),
            "ssh_port": self.ssh_port_var.get(),
            "share_path": self.share_path_var.get(),
            "share_owner": self.share_owner_var.get(),
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
        
        mode = self.mode_var.get()
        if mode == "local":
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
        else:
            # Remote mode
            parts.append("--remote-mode")
            if self.ssh_host_var.get(): parts.append(f'--ssh-host "{self.ssh_host_var.get()}"')
            if self.ssh_user_var.get(): parts.append(f'--ssh-user "{self.ssh_user_var.get()}"')
            if self.ssh_key_var.get(): parts.append(f'--ssh-key "{self.ssh_key_var.get()}"')
            if self.ssh_port_var.get() != "22": parts.append(f'--ssh-port {self.ssh_port_var.get()}')
            if self.share_path_var.get(): parts.append(f'--share-path "{self.share_path_var.get()}"')
            if self.share_owner_var.get(): parts.append(f'--share-owner "{self.share_owner_var.get()}"')
            
            cleanup_flags = []
            if self.cleanup_permissions_var.get(): cleanup_flags.append("--cleanup-permissions")
            if self.cleanup_empty_folders_var.get(): cleanup_flags.append("--cleanup-empty-folders")
            if self.cleanup_legacy_files_var.get(): cleanup_flags.append("--cleanup-legacy-files")
            if self.cleanup_filenames_var.get(): cleanup_flags.append("--cleanup-filenames")
            if not cleanup_flags: cleanup_flags.append("--cleanup-all")
            parts.extend(cleanup_flags)
            
        self.command_preview_var.set(" ".join(parts))

    def on_closing(self):
        """Handle the window closing event, saving settings before exit."""
        current_path = self.folder_path_var.get()
        if current_path and os.path.isdir(current_path):
            self.save_settings()
        self.destroy()

    def run_tasks(self):
        mode = self.mode_var.get()
        
        if mode == "local":
            folder_path = self.folder_path_var.get()
            if not folder_path or not os.path.isdir(folder_path):
                messagebox.showerror("Error", "Please select a valid folder.")
                return
        else:
            # Remote mode validation
            if not self.ssh_host_var.get() or not self.ssh_user_var.get() or not self.ssh_key_var.get():
                messagebox.showerror("Error", "Please provide SSH host, username, and key file.")
                return
            if not self.share_path_var.get() or not self.share_owner_var.get():
                messagebox.showerror("Error", "Please provide share path and share owner.")
                return
            if not os.path.exists(self.ssh_key_var.get()):
                messagebox.showerror("Error", f"SSH key file not found: {self.ssh_key_var.get()}")
                return
            if not (self.cleanup_permissions_var.get() or self.cleanup_empty_folders_var.get() or 
                    self.cleanup_legacy_files_var.get() or self.cleanup_filenames_var.get()):
                messagebox.showerror("Error", "Please select at least one cleanup operation.")
                return

        self.save_settings()

        if self.thread and self.thread.is_alive():
            messagebox.showwarning("Busy", "A task is already running.")
            return

        self.console.delete('1.0', tk.END) # Clear console
        self.run_button.config(state=tk.DISABLED, text="Running...")

        # Get settings from GUI
        if mode == "local":
            params = {
                "mode": "local",
                "folder_path": folder_path,
                "do_flatten": self.flatten_var.get(),
                "do_delete_dups": self.delete_dups_var.get(),
                "do_rename": self.rename_var.get(),
                "is_dry_run": self.dry_run_var.get(),
                "is_debug": self.debug_var.get(),
                "force_overwrite": self.force_overwrite_var.get(),
                "timezone": self.timezone_var.get() or None,
            }
        else:
            params = {
                "mode": "remote",
                "ssh_host": self.ssh_host_var.get(),
                "ssh_user": self.ssh_user_var.get(),
                "ssh_key": self.ssh_key_var.get(),
                "ssh_port": int(self.ssh_port_var.get() or "22"),
                "share_path": self.share_path_var.get(),
                "share_owner": self.share_owner_var.get(),
                "cleanup_permissions": self.cleanup_permissions_var.get(),
                "cleanup_empty_folders": self.cleanup_empty_folders_var.get(),
                "cleanup_legacy_files": self.cleanup_legacy_files_var.get(),
                "cleanup_filenames": self.cleanup_filenames_var.get(),
                "problem_chars": [c.strip() for c in self.problem_chars_var.get().split(',')],
                "exclude_folder": [p.strip() for p in self.exclude_folder_var.get().split(',')],
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
            if params["mode"] == "local":
                self.queue.put("--- Starting local mode tasks ---\n")
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
            else:
                # Remote mode
                self.queue.put("--- Starting remote SSH mode tasks ---\n")
                ssh_client = None
                try:
                    self.queue.put(f"Connecting to {params['ssh_host']}...\n")
                    ssh_client = connect_ssh(
                        params["ssh_host"],
                        params["ssh_user"],
                        params["ssh_key"],
                        params["ssh_port"]
                    )
                    self.queue.put("Connected successfully.\n\n")
                    
                    permission_issues = None
                    empty_folders = None
                    legacy_files = None
                    problematic_filenames = None
                    
                    if params["cleanup_permissions"]:
                        self.queue.put("Scanning for permission issues...\n")
                        permission_issues = scan_permission_issues(ssh_client, params["share_path"], params["share_owner"])
                        self.queue.put(f"Found {len(permission_issues['wrong_owner_files'])} files and {len(permission_issues['wrong_owner_dirs'])} directories with wrong ownership.\n\n")
                    
                    if params["cleanup_empty_folders"]:
                        self.queue.put("Scanning for empty folders...\n")
                        empty_folders = scan_empty_folders_remote(ssh_client, params["share_path"], params["exclude_folder"])
                        self.queue.put(f"Found {len(empty_folders)} empty folders.\n\n")
                    
                    if params["cleanup_legacy_files"]:
                        self.queue.put("Scanning for legacy files...\n")
                        legacy_files = scan_legacy_files_remote(ssh_client, params["share_path"])
                        total_legacy = len(legacy_files.get('files', [])) + len(legacy_files.get('directories', [])) + len(legacy_files.get('resource_forks', []))
                        self.queue.put(f"Found {total_legacy} legacy items to delete.\n\n")
                    
                    if params["cleanup_filenames"]:
                        self.queue.put("Scanning for problematic filenames...\n")
                        problematic_filenames = scan_problematic_filenames_remote(
                            ssh_client, params["share_path"], params["problem_chars"]
                        )
                        self.queue.put(f"Found {len(problematic_filenames)} files/directories with problematic characters.\n\n")
                    
                    self.queue.put("Generating cleanup scripts...\n")
                    output_dir, scripts = generate_categorized_cleanup_scripts(
                        share_path=params["share_path"],
                        username=params["share_owner"],
                        permission_issues=permission_issues,
                        empty_folders=empty_folders,
                        legacy_files=legacy_files,
                        problematic_filenames=problematic_filenames,
                        exclude_patterns=params["exclude_folder"]
                    )
                    
                    self.queue.put(f"\n=== Scripts generated successfully ===\n")
                    self.queue.put(f"Output directory: {os.path.abspath(output_dir)}\n")
                    self.queue.put(f"Scripts generated: {len(scripts)}\n")
                    for script in scripts:
                        self.queue.put(f"  - {os.path.basename(script)}\n")
                    self.queue.put(f"\nReview the scripts and run them on your QNAP SSH terminal.\n")
                    self.queue.put(f"To run all scripts: bash {os.path.join(output_dir, 'run_all.sh')}\n")
                finally:
                    if ssh_client:
                        disconnect_ssh(ssh_client)
                
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
    try:
        app = App()
        app.mainloop()
    except Exception as e:
        print(f"Error starting GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)