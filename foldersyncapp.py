#!/usr/bin/env python3
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
from sync import FolderSync
import stat  # Required for remote directory browser

class FolderSyncApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Folder Synchronization Tool")
        self.root.geometry("600x550")  # Slightly larger to accommodate new controls
        self.root.resizable(True, True)
        
        # Settings file path
        self.settings_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sync_settings.json")
        
        # SSH and SFTP connections
        self.ssh_client = None
        self.sftp_client = None
        
        # Sync status flags
        self.stop_requested = False
        
        # Create a style
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        
        # Main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # SSH Connection Frame
        self.ssh_frame = ttk.LabelFrame(self.main_frame, text="SSH Connection Details", padding="10")
        self.ssh_frame.pack(fill=tk.X, pady=5)
        
        # Host
        ttk.Label(self.ssh_frame, text="Host:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.host_var = tk.StringVar()
        ttk.Entry(self.ssh_frame, width=30, textvariable=self.host_var).grid(column=1, row=0, sticky=tk.W, padx=5)
        
        # Port
        ttk.Label(self.ssh_frame, text="Port:").grid(column=2, row=0, sticky=tk.W, pady=5)
        self.port_var = tk.StringVar(value="22")
        ttk.Entry(self.ssh_frame, width=6, textvariable=self.port_var).grid(column=3, row=0, sticky=tk.W, padx=5)
        
        # Username
        ttk.Label(self.ssh_frame, text="Username:").grid(column=0, row=1, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(self.ssh_frame, width=30, textvariable=self.username_var).grid(column=1, row=1, sticky=tk.W, padx=5)
        
        # Password
        ttk.Label(self.ssh_frame, text="Password:").grid(column=2, row=1, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.ssh_frame, width=20, textvariable=self.password_var, show="*")
        self.password_entry.grid(column=3, row=1, sticky=tk.W, padx=5)
        
        # Connect Button
        self.connect_button = ttk.Button(self.ssh_frame, text="Connect", command=self.connect_ssh)
        self.connect_button.grid(column=4, row=0, rowspan=2, padx=5, pady=5, sticky=tk.NS)
        
        # Directory Selection Frame
        self.dir_frame = ttk.LabelFrame(self.main_frame, text="Directory Selection", padding="10")
        self.dir_frame.pack(fill=tk.X, pady=5)
        
        # Local Directory
        ttk.Label(self.dir_frame, text="Local Directory:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.local_dir_var = tk.StringVar()
        ttk.Entry(self.dir_frame, width=40, textvariable=self.local_dir_var).grid(column=1, row=0, sticky=tk.EW, padx=5)
        ttk.Button(self.dir_frame, text="Browse...", command=self.browse_local_dir).grid(column=2, row=0, padx=5)
        
        # Remote Directory
        ttk.Label(self.dir_frame, text="Remote Directory:").grid(column=0, row=1, sticky=tk.W, pady=5)
        self.remote_dir_var = tk.StringVar()
        ttk.Entry(self.dir_frame, width=40, textvariable=self.remote_dir_var).grid(column=1, row=1, sticky=tk.EW, padx=5)
        
        # Remote Browse Button (Initially disabled)
        self.remote_browse_button = ttk.Button(self.dir_frame, text="Browse...", command=self.browse_remote_dir, state=tk.DISABLED)
        self.remote_browse_button.grid(column=2, row=1, padx=5)
        
        # Configure the grid to expand
        self.dir_frame.columnconfigure(1, weight=1)
        
        # Sync Options Frame
        self.options_frame = ttk.LabelFrame(self.main_frame, text="Sync Options", padding="10")
        self.options_frame.pack(fill=tk.X, pady=5)
        
        # Sync Direction
        ttk.Label(self.options_frame, text="Sync Direction:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.sync_direction = tk.StringVar(value="both")
        
        direction_frame = ttk.Frame(self.options_frame)
        direction_frame.grid(column=1, row=0, sticky=tk.W)
        
        ttk.Radiobutton(direction_frame, text="Both Ways", variable=self.sync_direction, value="both").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(direction_frame, text="Local → Remote", variable=self.sync_direction, value="to_remote").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(direction_frame, text="Remote → Local", variable=self.sync_direction, value="to_local").pack(side=tk.LEFT, padx=5)
        
        # File Extension Filter
        ttk.Label(self.options_frame, text="File Extension Filter:").grid(column=0, row=1, sticky=tk.W, pady=5)
        
        # Container for extension filter options
        filter_frame = ttk.Frame(self.options_frame)
        filter_frame.grid(column=1, row=1, sticky=tk.W)
        
        # Enable/disable extension filtering
        self.use_extension_filter = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_frame, text="Filter by Extension", variable=self.use_extension_filter).pack(side=tk.LEFT, padx=5)
        
        # Extensions entry
        ttk.Label(filter_frame, text="Extensions:").pack(side=tk.LEFT, padx=5)
        self.extensions_var = tk.StringVar()
        ttk.Entry(filter_frame, width=20, textvariable=self.extensions_var).pack(side=tk.LEFT, padx=5)
        ttk.Label(filter_frame, text="(comma-separated, e.g.: .txt,.pdf,.docx)").pack(side=tk.LEFT, padx=5)
        
        # Include/Exclude mode
        filter_mode_frame = ttk.Frame(self.options_frame)
        filter_mode_frame.grid(column=1, row=2, sticky=tk.W)
        
        self.extension_filter_mode = tk.StringVar(value="include")
        ttk.Radiobutton(filter_mode_frame, text="Include only these extensions", 
                       variable=self.extension_filter_mode, value="include").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(filter_mode_frame, text="Exclude these extensions", 
                       variable=self.extension_filter_mode, value="exclude").pack(side=tk.LEFT, padx=5)
        
        # Folder Exclusions
        ttk.Label(self.options_frame, text="Folder Exclusions:").grid(column=0, row=3, sticky=tk.W, pady=5)
        
        # Container for folder exclusion options
        folder_exclusion_frame = ttk.Frame(self.options_frame)
        folder_exclusion_frame.grid(column=1, row=3, sticky=tk.W)
        
        # Enable/disable folder exclusions
        self.use_folder_exclusions = tk.BooleanVar(value=False)
        ttk.Checkbutton(folder_exclusion_frame, text="Exclude Folders", 
                        variable=self.use_folder_exclusions).pack(side=tk.LEFT, padx=5)
        
        # Folder exclusions entry - using Text widget for multiline input
        ttk.Label(folder_exclusion_frame, text="Folders to exclude:").pack(side=tk.LEFT, padx=5)
        folder_text_frame = ttk.Frame(self.options_frame)
        folder_text_frame.grid(column=1, row=4, sticky=tk.W, pady=5)
        
        # Scrollable text area for folder exclusions
        self.folder_exclusions_text = tk.Text(folder_text_frame, width=40, height=3, wrap=tk.WORD)
        self.folder_exclusions_text.pack(side=tk.LEFT, padx=5)
        folder_scroll = ttk.Scrollbar(folder_text_frame, command=self.folder_exclusions_text.yview)
        folder_scroll.pack(side=tk.LEFT, fill=tk.Y)
        self.folder_exclusions_text.config(yscrollcommand=folder_scroll.set)
        
        ttk.Label(folder_text_frame, text="(one per line, e.g.: tmp, .git, logs)").pack(side=tk.LEFT, padx=5)
        
        # Comparison Method
        ttk.Label(self.options_frame, text="Comparison Method:").grid(column=0, row=5, sticky=tk.W, pady=5)
        
        compare_frame = ttk.Frame(self.options_frame)
        compare_frame.grid(column=1, row=5, sticky=tk.W)
        
        self.compare_method = tk.StringVar(value="quick")
        ttk.Radiobutton(compare_frame, text="Quick (size and time)", 
                       variable=self.compare_method, value="quick").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(compare_frame, text="Content-only (MD5 hash)", 
                       variable=self.compare_method, value="content").pack(side=tk.LEFT, padx=5)
        
        # Save settings option
        self.save_settings_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.options_frame, text="Save Settings", variable=self.save_settings_var).grid(column=0, row=6, sticky=tk.W)
        
        # Action Frame (Sync Button)
        self.action_frame = ttk.Frame(self.main_frame, padding="10")
        self.action_frame.pack(fill=tk.X, pady=5)
        
        # Button container for side-by-side buttons
        self.button_container = ttk.Frame(self.action_frame)
        self.button_container.pack(fill=tk.X)
        
        # Sync Button
        self.sync_button = ttk.Button(self.button_container, text="Start Synchronization", command=self.start_sync)
        self.sync_button.pack(side=tk.LEFT, pady=10, padx=5)
        
        # Stop Sync Button (initially disabled)
        self.stop_button = ttk.Button(self.button_container, text="Stop Sync", command=self.stop_sync, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, pady=10, padx=5)
        
        # Save Settings Button
        self.save_button = ttk.Button(self.button_container, text="Save Settings", command=self.save_settings)
        self.save_button.pack(side=tk.LEFT, pady=10, padx=5)
        
        # Disconnect Button (Initially disabled)
        self.disconnect_button = ttk.Button(self.button_container, text="Disconnect", command=self.disconnect_ssh, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, pady=10, padx=5)
        
        # Progress Frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Progress", padding="10")
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, 
                                           length=100, mode='determinate', 
                                           variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Status Label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.progress_frame, textvariable=self.status_var)
        self.status_label.pack(fill=tk.X, pady=5)
        
        # Log Frame
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Log", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Log Text
        self.log_text = tk.Text(self.log_frame, height=10, width=70, wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Enable text selection and copying
        self.log_text.config(state=tk.NORMAL)
        
        # Scrollbar for Log
        scrollbar = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # Set the initial state of the log
        self.log_text.config(state=tk.DISABLED)
        
        # Sync thread
        self.sync_thread = None
        
        # Load settings
        self.load_settings()
        
        # Bind window close event to save settings
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def connect_ssh(self):
        """Establish SSH connection to the remote server"""
        host = self.host_var.get().strip()
        port = self.port_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        # Basic validation
        if not host:
            messagebox.showerror("Error", "Please enter SSH host")
            return
        if not port.isdigit():
            messagebox.showerror("Error", "Port must be a number")
            return
        if not username:
            messagebox.showerror("Error", "Please enter SSH username")
            return
        if not password:
            messagebox.showerror("Error", "Please enter SSH password")
            return
        
        self.log_message(f"Connecting to {username}@{host}:{port}...")
        self.status_var.set("Connecting...")
        
        # Disable connect button during connection attempt
        self.connect_button.config(state=tk.DISABLED)
        
        # Start connection in a separate thread to avoid freezing the UI
        threading.Thread(target=self._connect_ssh_thread, 
                        args=(host, int(port), username, password),
                        daemon=True).start()
    
    def _connect_ssh_thread(self, host, port, username, password):
        """Thread function to establish SSH connection"""
        import paramiko
        
        try:
            # Create client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            client.connect(hostname=host, port=port, username=username, password=password)
            
            # Store client and open SFTP
            self.ssh_client = client
            self.sftp_client = client.open_sftp()
            
            # Update UI on success
            self.root.after(0, self._on_ssh_connected)
            
        except Exception as e:
            error_msg = f"Connection failed: {str(e)}"
            self.root.after(0, lambda: self._on_ssh_error(error_msg))
    
    def _on_ssh_connected(self):
        """Called when SSH connection succeeds"""
        self.log_message("Connection established successfully")
        self.status_var.set("Connected")
        
        # Enable remote directory browsing
        self.remote_browse_button.config(state=tk.NORMAL)
        
        # Enable disconnect button
        self.disconnect_button.config(state=tk.NORMAL)
        
        # Disable connection fields
        self._set_connection_fields_state(tk.DISABLED)
    
    def _on_ssh_error(self, error_msg):
        """Called when SSH connection fails"""
        self.log_message(error_msg)
        self.status_var.set("Connection failed")
        self.connect_button.config(state=tk.NORMAL)
    
    def disconnect_ssh(self):
        """Disconnect from SSH server"""
        if self.sftp_client:
            try:
                self.sftp_client.close()
            except:
                pass
            self.sftp_client = None
            
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass
            self.ssh_client = None
        
        # Reset UI state
        self.remote_browse_button.config(state=tk.DISABLED)
        self.disconnect_button.config(state=tk.DISABLED)
        self._set_connection_fields_state(tk.NORMAL)
        
        self.log_message("Disconnected from server")
        self.status_var.set("Disconnected")
    
    def _set_connection_fields_state(self, state):
        """Enable or disable connection input fields"""
        self.connect_button.config(state=state)
        for widget in self.ssh_frame.winfo_children():
            if isinstance(widget, ttk.Entry) or isinstance(widget, ttk.Button):
                if widget != self.connect_button and widget != self.disconnect_button:
                    widget.config(state=state)
    
    def browse_local_dir(self):
        """Open file dialog to select local directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.local_dir_var.set(directory)
    
    def browse_remote_dir(self):
        """Browse remote directories"""
        if not self.sftp_client:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        # Create a dialog to browse remote directories
        remote_browser = RemoteDirectoryBrowser(self.root, self.sftp_client, self.remote_dir_var.get())
        if remote_browser.result:
            self.remote_dir_var.set(remote_browser.result)
    
    def progress_callback(self, status_message=None, progress=None, log_message=None):
        """Callback function to update GUI from the sync process"""
        if status_message:
            self.status_var.set(status_message)
        
        if progress is not None:
            self.progress_var.set(progress)
        
        if log_message:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, log_message + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        
        self.root.update_idletasks()
    
    def save_settings(self):
        """Save current settings to a file"""
        settings = {
            'host': self.host_var.get().strip(),
            'port': self.port_var.get().strip(),
            'username': self.username_var.get().strip(),
            'local_dir': self.local_dir_var.get().strip(),
            'remote_dir': self.remote_dir_var.get().strip(),
            'sync_direction': self.sync_direction.get(),
            'use_extension_filter': self.use_extension_filter.get(),
            'extensions': self.extensions_var.get().strip(),
            'extension_filter_mode': self.extension_filter_mode.get(),
            'use_folder_exclusions': self.use_folder_exclusions.get(),
            'folder_exclusions': self.folder_exclusions_text.get(1.0, tk.END).strip(),
            'compare_method': self.compare_method.get()
        }
        
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f)
            self.log_message("Settings saved successfully")
        except Exception as e:
            self.log_message(f"Error saving settings: {str(e)}")
    
    def load_settings(self):
        """Load settings from file"""
        if not os.path.exists(self.settings_file):
            self.log_message("No saved settings found.")
            return
        
        try:
            with open(self.settings_file, 'r') as f:
                settings = json.load(f)
            
            self.host_var.set(settings.get('host', ''))
            self.port_var.set(settings.get('port', '22'))
            self.username_var.set(settings.get('username', ''))
            self.local_dir_var.set(settings.get('local_dir', ''))
            self.remote_dir_var.set(settings.get('remote_dir', ''))
            self.sync_direction.set(settings.get('sync_direction', 'both'))
            self.use_extension_filter.set(settings.get('use_extension_filter', False))
            self.extensions_var.set(settings.get('extensions', ''))
            self.extension_filter_mode.set(settings.get('extension_filter_mode', 'include'))
            self.use_folder_exclusions.set(settings.get('use_folder_exclusions', False))
            
            # Load folder exclusions into text widget
            folder_exclusions = settings.get('folder_exclusions', '')
            self.folder_exclusions_text.delete(1.0, tk.END)
            self.folder_exclusions_text.insert(tk.END, folder_exclusions)
            
            self.compare_method.set(settings.get('compare_method', 'quick'))
            
            self.log_message("Settings loaded successfully")
        except Exception as e:
            self.log_message(f"Error loading settings: {str(e)}")
    
    def log_message(self, message):
        """Add a message to the log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def on_closing(self):
        """Function called when the window is closing"""
        if self.save_settings_var.get():
            self.save_settings()
        
        # Close connections
        self.disconnect_ssh()
        
        self.root.destroy()
    
    def get_cache_file_paths(self, local_dir, remote_dir, host):
        """Generate cache file paths based on sync directories"""
        if not local_dir:
            return None, None
            
        # Create cache directory inside the local folder
        cache_dir = os.path.join(local_dir, ".synccache")
        try:
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
        except Exception as e:
            self.log_message(f"Error creating cache directory in local folder: {str(e)}")
            return None, None
            
        # Create safe filenames from paths
        def make_safe_filename(path, prefix):
            # Replace non-alphanumeric characters with underscores
            safe_path = "".join([c if c.isalnum() else "_" for c in path])
            # Ensure the name is not too long
            if len(safe_path) > 100:
                safe_path = safe_path[:50] + "__" + safe_path[-48:]
            return f"{prefix}_{host}_{safe_path}.json"
        
        local_cache = os.path.join(cache_dir, make_safe_filename(local_dir, "local"))
        remote_cache = os.path.join(cache_dir, make_safe_filename(remote_dir, "remote"))
        
        return local_cache, remote_cache
    
    def start_sync(self):
        """Start the synchronization process in a separate thread"""
        # Validate inputs
        host = self.host_var.get().strip()
        port = self.port_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        local_dir = self.local_dir_var.get().strip()
        remote_dir = self.remote_dir_var.get().strip()
        
        if not host:
            messagebox.showerror("Error", "Please enter SSH host")
            return
        if not port.isdigit():
            messagebox.showerror("Error", "Port must be a number")
            return
        if not username:
            messagebox.showerror("Error", "Please enter SSH username")
            return
        if not password:
            messagebox.showerror("Error", "Please enter SSH password")
            return
        if not local_dir:
            messagebox.showerror("Error", "Please select local directory")
            return
        if not remote_dir:
            messagebox.showerror("Error", "Please enter remote directory")
            return
        
        # Determine bidirectional setting from sync_direction
        sync_direction = self.sync_direction.get()
        bidirectional = sync_direction == "both"
        
        # For one-way sync, we need to set the sync mode in the FolderSync class
        sync_mode = "both"
        if sync_direction == "to_remote":
            sync_mode = "to_remote"
        elif sync_direction == "to_local":
            sync_mode = "to_local"
        
        # Process extension filters
        extension_filters = []
        if self.use_extension_filter.get():
            extensions = self.extensions_var.get().strip()
            if extensions:
                # Convert comma-separated list to proper filter patterns
                for ext in extensions.split(','):
                    ext = ext.strip()
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    extension_filters.append('*' + ext)
        
        # Process folder exclusions
        folder_exclusions = []
        if self.use_folder_exclusions.get():
            exclusions_text = self.folder_exclusions_text.get(1.0, tk.END).strip()
            if exclusions_text:
                # Convert multiline text to list, removing empty lines
                for line in exclusions_text.split('\n'):
                    folder = line.strip()
                    if folder:
                        folder_exclusions.append(folder)
        
        # Get comparison method
        content_only_compare = self.compare_method.get() == "content"
        
        # Save settings if option is selected
        if self.save_settings_var.get():
            self.save_settings()
        
        # Reset stop flag
        self.stop_requested = False
        
        # Disable the sync button and enable stop button while syncing
        self.sync_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Clear log
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Reset progress
        self.progress_var.set(0)
        self.status_var.set("Initializing...")
        
        # Generate cache file paths
        local_cache_file, remote_cache_file = self.get_cache_file_paths(local_dir, remote_dir, host)
        
        # Determine number of CPU cores to use (use all available cores)
        import multiprocessing
        max_workers = multiprocessing.cpu_count()
        
        # Create the sync instance with cache file paths and multiprocessing support
        syncer = FolderSync(
            callback=self.progress_callback,
            local_cache_file=local_cache_file,
            remote_cache_file=remote_cache_file,
            max_workers=max_workers
        )
        
        # Log cache status
        if local_cache_file and remote_cache_file:
            self.log_message("Using metadata cache for optimized synchronization")
        
        # Log comparison method
        if content_only_compare:
            self.log_message("Using content-only comparison (MD5 hash)")
        else:
            self.log_message("Using quick comparison (size and modification time)")
            
        # Log folder exclusions if any
        if folder_exclusions:
            self.log_message(f"Excluding folders: {', '.join(folder_exclusions)}")
            
        # Log multiprocessing information
        self.log_message(f"Using up to {max_workers} CPU cores for parallel processing")
        
        # Start sync thread
        self.sync_thread = threading.Thread(
            target=self.run_sync,
            args=(syncer, host, int(port), username, password, local_dir, remote_dir, 
                  bidirectional, sync_mode, extension_filters, self.extension_filter_mode.get(),
                  folder_exclusions, content_only_compare)
        )
        self.sync_thread.daemon = True
        self.sync_thread.start()
    
    def run_sync(self, syncer, host, port, username, password, local_dir, remote_dir, 
                bidirectional, sync_mode, extension_filters, filter_mode,
                folder_exclusions, content_only_compare):
        """Run the sync process and re-enable the sync button when done"""
        try:
            # Use existing connection if available
            if self.ssh_client and self.sftp_client:
                # Use existing connection
                result = syncer.sync_with_existing_connection(
                    self.ssh_client, self.sftp_client, local_dir, remote_dir, bidirectional, 
                    sync_mode, extension_filters, filter_mode, lambda: self.stop_requested,
                    folder_exclusions, content_only_compare
                )
            else:
                # Create new connection
                result = syncer.sync_directories(
                    host, port, username, password, local_dir, remote_dir, bidirectional, 
                    sync_mode, extension_filters, filter_mode, lambda: self.stop_requested,
                    folder_exclusions, content_only_compare
                )
                
            # Check if sync was stopped
            if self.stop_requested:
                self.log_message("Synchronization was stopped by user")
                self.status_var.set("Synchronization stopped")
        except Exception as e:
            self.log_message(f"Error during synchronization: {str(e)}")
            self.status_var.set("Synchronization failed")
        finally:
            # Reset stop flag
            self.stop_requested = False
            
            # Re-enable the sync button and disable stop button when done
            self.root.after(0, lambda: self.sync_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
    
    def stop_sync(self):
        """Signal the sync process to stop"""
        if self.sync_thread and self.sync_thread.is_alive():
            self.stop_requested = True
            self.status_var.set("Stopping synchronization...")
            self.log_message("Stopping synchronization...")
            self.stop_button.config(state=tk.DISABLED)


class RemoteDirectoryBrowser(tk.Toplevel):
    def __init__(self, parent, sftp, initial_path="/"):
        super().__init__(parent)
        
        self.title("Browse Remote Directory")
        self.geometry("400x300")
        self.transient(parent)
        self.grab_set()
        
        self.sftp = sftp
        self.current_path = initial_path if initial_path else "/"
        self.result = None
        
        # Current path display
        self.path_frame = ttk.Frame(self)
        self.path_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(self.path_frame, text="Path:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar(value=self.current_path)
        path_entry = ttk.Entry(self.path_frame, textvariable=self.path_var, width=40)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        path_entry.bind("<Return>", self.navigate_to_path)
        
        # Directory listing
        self.list_frame = ttk.Frame(self)
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.dir_listbox = tk.Listbox(self.list_frame)
        self.dir_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.list_frame, orient=tk.VERTICAL, command=self.dir_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dir_listbox.config(yscrollcommand=scrollbar.set)
        
        # Double-click to navigate or select
        self.dir_listbox.bind("<Double-1>", self.on_item_double_click)
        
        # Button frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Select Current Directory", command=self.select_current).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).pack(side=tk.RIGHT, padx=5)
        
        # Load initial directory contents
        self.refresh_directory_list()
        
        # Make dialog modal
        self.wait_window()
    
    def refresh_directory_list(self):
        """Refresh the directory listing"""
        self.dir_listbox.delete(0, tk.END)
        
        try:
            # Add parent directory option
            self.dir_listbox.insert(tk.END, "../ (Parent Directory)")
            
            # List directories and files
            for entry in sorted(self.sftp.listdir(self.current_path)):
                try:
                    # Check if it's a directory
                    path = os.path.join(self.current_path, entry).replace("\\", "/")
                    if path.endswith("/") and path != "/":
                        path = path[:-1]
                        
                    attr = self.sftp.stat(path)
                    if stat.S_ISDIR(attr.st_mode):
                        self.dir_listbox.insert(tk.END, entry + "/")
                    else:
                        self.dir_listbox.insert(tk.END, entry)
                except:
                    # Skip entries that cause errors
                    continue
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read directory: {str(e)}")
    
    def navigate_to_path(self, event=None):
        """Navigate to the path entered in the path entry"""
        new_path = self.path_var.get().strip()
        if new_path:
            try:
                # Check if path exists and is a directory
                attr = self.sftp.stat(new_path)
                if stat.S_ISDIR(attr.st_mode):
                    self.current_path = new_path
                    self.path_var.set(self.current_path)
                    self.refresh_directory_list()
                else:
                    messagebox.showerror("Error", "Not a directory")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid path: {str(e)}")
    
    def on_item_double_click(self, event):
        """Handle double-click on an item"""
        selection = self.dir_listbox.curselection()
        if not selection:
            return
            
        item = self.dir_listbox.get(selection[0])
        
        if item == "../ (Parent Directory)":
            # Navigate to parent directory
            parent = os.path.dirname(self.current_path)
            self.current_path = parent if parent else "/"
            self.path_var.set(self.current_path)
            self.refresh_directory_list()
        elif item.endswith("/"):
            # Navigate to subdirectory
            dir_name = item[:-1]  # Remove trailing slash
            new_path = os.path.join(self.current_path, dir_name).replace("\\", "/")
            self.current_path = new_path
            self.path_var.set(self.current_path)
            self.refresh_directory_list()
    
    def select_current(self):
        """Select the current directory and close"""
        self.result = self.current_path
        self.destroy()
    
    def cancel(self):
        """Cancel selection and close"""
        self.result = None
        self.destroy()


def main():
    root = tk.Tk()
    app = FolderSyncApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()