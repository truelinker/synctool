#!/usr/bin/env python3
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
from sync import FolderSync
import stat  # Required for remote directory browser
import traceback
import time
import paramiko

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
        self.style.configure("TButton", padding=4, relief="flat", background="#ccc")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 9))
        self.style.configure("Header.TLabel", font=("Arial", 11, "bold"))
        
        # Main frame
        self.main_frame = ttk.Frame(root, padding="5")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # SSH Connection Frame
        self.ssh_frame = ttk.LabelFrame(self.main_frame, text="SSH Connection", padding="5")
        self.ssh_frame.pack(fill=tk.X, pady=2)
        
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
        
        # Disconnect Button (Initially disabled)
        self.disconnect_button = ttk.Button(self.ssh_frame, text="Disconnect", command=self.disconnect_ssh, state=tk.DISABLED)
        self.disconnect_button.grid(column=5, row=0, rowspan=2, padx=5, pady=5, sticky=tk.NS)
        
        # ----- COMMON FOLDER SELECTION FRAME -----
        
        # Folder Selection Frame
        self.folder_frame = ttk.LabelFrame(self.main_frame, text="Folders", padding="5")
        self.folder_frame.pack(fill=tk.X, pady=2)
        
        # Local Folder
        ttk.Label(self.folder_frame, text="Local Folder:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.local_folder_var = tk.StringVar()
        local_entry = ttk.Entry(self.folder_frame, width=40, textvariable=self.local_folder_var)
        local_entry.grid(column=1, row=0, sticky=tk.EW, padx=5)
        
        # Browse button for local folder
        self.local_browse_button = ttk.Button(self.folder_frame, text="Browse...", 
                                            command=self.browse_local_folder)
        self.local_browse_button.grid(column=2, row=0, padx=5)
        
        # Remote Folder
        ttk.Label(self.folder_frame, text="Remote Folder:").grid(column=0, row=1, sticky=tk.W, pady=5)
        self.remote_folder_var = tk.StringVar()
        remote_entry = ttk.Entry(self.folder_frame, width=40, textvariable=self.remote_folder_var)
        remote_entry.grid(column=1, row=1, sticky=tk.EW, padx=5)
        
        # Browse button for remote folder
        self.remote_browse_button = ttk.Button(self.folder_frame, text="Browse...", 
                                             command=self.browse_remote_folder, state=tk.DISABLED)
        self.remote_browse_button.grid(column=2, row=1, padx=5)
        
        # Configure grid expansion
        self.folder_frame.columnconfigure(1, weight=1)
        
        # ----- OPTIONS CONTAINER FRAME -----
        
        # Create a frame to hold the side-by-side options
        self.options_container = ttk.Frame(self.main_frame)
        self.options_container.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Configure columns for side-by-side layout
        self.options_container.columnconfigure(0, weight=1)
        self.options_container.columnconfigure(1, weight=1)
        
        # ----- FILE TRANSFER SECTION -----
        
        # Transfer Frame (left column)
        self.transfer_frame = ttk.LabelFrame(self.options_container, text="File Transfer", padding="5")
        self.transfer_frame.grid(column=0, row=0, sticky=tk.NSEW, padx=(0, 2))
        
        # Transfer direction
        ttk.Label(self.transfer_frame, text="Transfer Direction:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.transfer_direction = tk.StringVar(value="upload")
        
        direction_frame = ttk.Frame(self.transfer_frame)
        direction_frame.grid(column=1, row=0, sticky=tk.W)
        
        ttk.Radiobutton(direction_frame, text="Upload (Local → Remote)", 
                      variable=self.transfer_direction, value="upload").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(direction_frame, text="Download (Remote → Local)", 
                      variable=self.transfer_direction, value="download").pack(side=tk.LEFT, padx=5)
        
        # Add trace to handle direction change
        self.transfer_direction.trace_add("write", self.on_transfer_direction_change)
        
        # Transfer options - Folder Exclusions
        ttk.Label(self.transfer_frame, text="Folder Exclusions:").grid(column=0, row=1, sticky=tk.W, pady=5)
        
        # Container for folder exclusion options
        exclusion_frame = ttk.Frame(self.transfer_frame)
        exclusion_frame.grid(column=1, row=1, sticky=tk.W)
        
        # Enable/disable folder exclusions
        self.transfer_use_exclusions = tk.BooleanVar(value=False)
        ttk.Checkbutton(exclusion_frame, text="Exclude Folders", 
                      variable=self.transfer_use_exclusions).pack(side=tk.LEFT, padx=5)
        
        # Create exclusion list component
        self.transfer_exclusions_component = self.create_exclusion_list_frame(self.transfer_frame, "Folders to exclude")
        self.transfer_exclusions_component["frame"].grid(column=0, row=2, columnspan=2, sticky=tk.EW, pady=5)
        
        # Compression options
        compression_frame = ttk.Frame(self.transfer_frame)
        compression_frame.grid(column=0, row=3, columnspan=2, sticky=tk.W, pady=5)
        
        # Use compression checkbox
        self.use_compression = tk.BooleanVar(value=True)
        ttk.Checkbutton(compression_frame, text="Use Compression", 
                       variable=self.use_compression).pack(side=tk.LEFT, padx=5)
        
        # Compression level options
        ttk.Label(compression_frame, text="Compression Level:").pack(side=tk.LEFT, padx=5)
        self.compression_level = tk.StringVar(value="balanced")
        ttk.Radiobutton(compression_frame, text="Fast", 
                       variable=self.compression_level, value="fast").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(compression_frame, text="Balanced", 
                       variable=self.compression_level, value="balanced").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(compression_frame, text="Maximum", 
                       variable=self.compression_level, value="maximum").pack(side=tk.LEFT, padx=5)
        
        # Skip already compressed files checkbox
        self.skip_compressed = tk.BooleanVar(value=True)
        skip_compressed_frame = ttk.Frame(self.transfer_frame)
        skip_compressed_frame.grid(column=0, row=4, columnspan=2, sticky=tk.W, pady=5)
        ttk.Checkbutton(skip_compressed_frame, text="Skip Already Compressed Files", 
                       variable=self.skip_compressed).pack(side=tk.LEFT, padx=5)
        
        # Extract archives checkbox
        self.extract_archives = tk.BooleanVar(value=True)
        extract_archives_frame = ttk.Frame(self.transfer_frame)
        extract_archives_frame.grid(column=0, row=5, columnspan=2, sticky=tk.W, pady=5)
        ttk.Checkbutton(extract_archives_frame, text="Extract Archives on Destination",
                         variable=self.extract_archives).pack(side=tk.LEFT, padx=5)
        
        # Transfer action buttons
        transfer_button_frame = ttk.Frame(self.transfer_frame)
        transfer_button_frame.grid(column=0, row=6, columnspan=2, pady=10)
        
        # Transfer button
        self.transfer_button = ttk.Button(transfer_button_frame, text="Start File Transfer", 
                                        command=self.start_transfer)
        self.transfer_button.pack(side=tk.LEFT, padx=5)
        
        # Configure grid expansion
        self.transfer_frame.columnconfigure(1, weight=1)
        
        # ----- SYNC SECTION -----
        
        # Sync Options Frame (right column)
        self.sync_frame = ttk.LabelFrame(self.options_container, text="Synchronization", padding="5")
        self.sync_frame.grid(column=1, row=0, sticky=tk.NSEW, padx=(2, 0))
        
        # Sync Direction
        ttk.Label(self.sync_frame, text="Sync Direction:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.sync_direction = tk.StringVar(value="both")
        
        sync_direction_frame = ttk.Frame(self.sync_frame)
        sync_direction_frame.grid(column=1, row=0, sticky=tk.W)
        
        ttk.Radiobutton(sync_direction_frame, text="Both Ways", 
                      variable=self.sync_direction, value="both").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(sync_direction_frame, text="Local → Remote", 
                      variable=self.sync_direction, value="to_remote").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(sync_direction_frame, text="Remote → Local", 
                      variable=self.sync_direction, value="to_local").pack(side=tk.LEFT, padx=5)
        
        # File Extension Filter
        ttk.Label(self.sync_frame, text="File Extension Filter:").grid(column=0, row=1, sticky=tk.W, pady=5)
        
        # Container for extension filter options
        filter_frame = ttk.Frame(self.sync_frame)
        filter_frame.grid(column=1, row=1, sticky=tk.W)
        
        # Enable/disable extension filtering
        self.use_extension_filter = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_frame, text="Filter by Extension", 
                      variable=self.use_extension_filter).pack(side=tk.LEFT, padx=5)
        
        # Extensions entry
        ttk.Label(filter_frame, text="Extensions:").pack(side=tk.LEFT, padx=5)
        self.extensions_var = tk.StringVar()
        ttk.Entry(filter_frame, width=20, textvariable=self.extensions_var).pack(side=tk.LEFT, padx=5)
        
        # Include/Exclude mode
        filter_mode_frame = ttk.Frame(self.sync_frame)
        filter_mode_frame.grid(column=1, row=2, sticky=tk.W)
        
        self.extension_filter_mode = tk.StringVar(value="include")
        ttk.Radiobutton(filter_mode_frame, text="Include only these extensions", 
                       variable=self.extension_filter_mode, value="include").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(filter_mode_frame, text="Exclude these extensions", 
                       variable=self.extension_filter_mode, value="exclude").pack(side=tk.LEFT, padx=5)
        
        # Folder Exclusions
        ttk.Label(self.sync_frame, text="Folder Exclusions:").grid(column=0, row=3, sticky=tk.W, pady=5)
        
        # Container for folder exclusion options
        folder_exclusion_frame = ttk.Frame(self.sync_frame)
        folder_exclusion_frame.grid(column=1, row=3, sticky=tk.W)
        
        # Enable/disable folder exclusions
        self.use_folder_exclusions = tk.BooleanVar(value=False)
        ttk.Checkbutton(folder_exclusion_frame, text="Exclude Folders", 
                        variable=self.use_folder_exclusions).pack(side=tk.LEFT, padx=5)
        
        # Create exclusion list component
        self.folder_exclusions_component = self.create_exclusion_list_frame(self.sync_frame, "Folders to exclude")
        self.folder_exclusions_component["frame"].grid(column=0, row=4, columnspan=2, sticky=tk.EW, pady=5)
        
        # Comparison Method
        ttk.Label(self.sync_frame, text="Comparison Method:").grid(column=0, row=5, sticky=tk.W, pady=5)
        
        compare_frame = ttk.Frame(self.sync_frame)
        compare_frame.grid(column=1, row=5, sticky=tk.W)
        
        self.compare_method = tk.StringVar(value="quick")
        ttk.Radiobutton(compare_frame, text="Quick (size and time)", 
                       variable=self.compare_method, value="quick").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(compare_frame, text="Content-only (MD5 hash)", 
                       variable=self.compare_method, value="content").pack(side=tk.LEFT, padx=5)
        
        # Transfer Method
        ttk.Label(self.sync_frame, text="Transfer Method:").grid(column=0, row=6, sticky=tk.W, pady=5)
        
        transfer_frame = ttk.Frame(self.sync_frame)
        transfer_frame.grid(column=1, row=6, sticky=tk.W)
        
        self.transfer_method = tk.StringVar(value="sftp")
        ttk.Radiobutton(transfer_frame, text="SFTP", 
                      variable=self.transfer_method, value="sftp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(transfer_frame, text="SCP", 
                      variable=self.transfer_method, value="scp").pack(side=tk.LEFT, padx=5)
        
        # Add Force Sync option
        ttk.Label(self.sync_frame, text="Debug Options:").grid(column=0, row=7, sticky=tk.W, pady=5)
        
        debug_frame = ttk.Frame(self.sync_frame)
        debug_frame.grid(column=1, row=7, sticky=tk.W)
        
        self.force_sync_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(debug_frame, text="Force Sync (override comparison)", 
                      variable=self.force_sync_var).pack(side=tk.LEFT, padx=5)
        
        # Add Use Cache Only option
        self.use_cache_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(debug_frame, text="Use Cache Only (faster)",
                      variable=self.use_cache_only_var).pack(side=tk.LEFT, padx=5)
        
        # Add Generate Cache button
        self.generate_cache_button = ttk.Button(debug_frame, text="Generate Cache", 
                                             command=self.generate_cache)
        self.generate_cache_button.pack(side=tk.LEFT, padx=5)
        
        # Sync action buttons
        sync_button_frame = ttk.Frame(self.sync_frame)
        sync_button_frame.grid(column=0, row=8, columnspan=2, pady=10)
        
        # Sync Button
        self.sync_button = ttk.Button(sync_button_frame, text="Start Synchronization", 
                                     command=self.start_sync)
        self.sync_button.pack(side=tk.LEFT, padx=5)
        
        # Configure grid expansion
        self.sync_frame.columnconfigure(1, weight=1)
        
        # ----- COMMON CONTROLS -----
        
        # Common button frame
        common_button_frame = ttk.Frame(self.main_frame)
        common_button_frame.pack(fill=tk.X, pady=2)
        
        # Save settings option - left side
        self.save_settings_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(common_button_frame, text="Auto-Save Settings", 
                       variable=self.save_settings_var).pack(side=tk.LEFT)
        
        # Tooltip explanation (as a small label)
        ttk.Label(common_button_frame, text="(on exit)", 
                 font=("Arial", 8)).pack(side=tk.LEFT, padx=(0, 10))
        
        # Save button - only when needed
        self.save_button = ttk.Button(common_button_frame, text="Save Now", 
                                    command=self.save_settings, width=8)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Stop button - right side
        self.stop_button = ttk.Button(common_button_frame, text="Stop Operation", 
                                    command=self.stop_sync, state=tk.DISABLED, width=12)
        self.stop_button.pack(side=tk.RIGHT, padx=5)
        
        # Progress Frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Progress", padding="5")
        self.progress_frame.pack(fill=tk.X, pady=2)
        
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
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Log", padding="5")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=2)
        
        # Log Text
        self.log_text = tk.Text(self.log_frame, height=6, width=70, wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Enable text selection and copying
        self.log_text.config(state=tk.NORMAL)
        
        # Scrollbar for Log
        scrollbar = ttk.Scrollbar(self.log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
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
        try:
            # Create client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            client.connect(hostname=host, port=port, username=username, password=password)
            
            # Store client and open SFTP
            self.ssh_client = client
            self.sftp_client = client.open_sftp()
            
            # Add after creating the SSH client
            transport = self.ssh_client.get_transport()
            if transport:
                transport.set_keepalive(60)  # Send keepalive packet every 60 seconds
            
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
    
    def browse_local_folder(self):
        """Browse for local folder"""
        folder = filedialog.askdirectory(title="Select Local Folder")
        if folder:
            self.local_folder_var.set(folder)
    
    def browse_remote_folder(self):
        """Browse for remote folder"""
        if not self.ssh_client or not self.sftp_client:
            messagebox.showerror("Error", "You must connect to SSH first")
            return
        
        # Create a simple dialog to browse remote directories
        dialog = tk.Toplevel(self.root)
        dialog.title("Browse Remote Folder")
        dialog.geometry("500x400")
        dialog.transient(self.root)  # Set to be on top of the main window
        dialog.grab_set()  # Modal
        
        # Current path
        current_path = "/"
        path_var = tk.StringVar(value=current_path)
        
        # Create frames
        path_frame = ttk.Frame(dialog, padding="10")
        path_frame.pack(fill=tk.X)
        
        list_frame = ttk.Frame(dialog, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(dialog, padding="10")
        button_frame.pack(fill=tk.X)
        
        # Path entry
        ttk.Label(path_frame, text="Path:").pack(side=tk.LEFT, padx=5)
        path_entry = ttk.Entry(path_frame, textvariable=path_var, width=50)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Directory listbox with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        dir_listbox = tk.Listbox(list_frame, width=60, height=15)
        dir_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        dir_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=dir_listbox.yview)
        
        # Buttons
        select_button = ttk.Button(button_frame, text="Select", width=10)
        select_button.pack(side=tk.RIGHT, padx=5)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", width=10, command=dialog.destroy)
        cancel_button.pack(side=tk.RIGHT, padx=5)
        
        # Populate the listbox
        def populate_listbox(path):
            dir_listbox.delete(0, tk.END)
            try:
                items = self.sftp_client.listdir(path)
                
                # Add parent directory option if not at root
                if path != "/":
                    dir_listbox.insert(tk.END, "../")
                
                # Add directories first
                dirs = []
                files = []
                
                for item in items:
                    try:
                        item_path = os.path.join(path, item).replace('\\', '/')
                        stat_result = self.sftp_client.stat(item_path)
                        if stat.S_ISDIR(stat_result.st_mode):
                            dirs.append(item + "/")
                        else:
                            files.append(item)
                    except:
                        files.append(item)  # If we can't determine, treat as file
                
                # Sort alphabetically
                dirs.sort()
                files.sort()
                
                # Add to listbox
                for d in dirs:
                    dir_listbox.insert(tk.END, d)
                for f in files:
                    dir_listbox.insert(tk.END, f)
                
            except Exception as e:
                messagebox.showerror("Error", f"Error listing directory: {str(e)}")
        
        # Handle double-click on dir
        def on_dir_double_click(event):
            selection = dir_listbox.curselection()
            if selection:
                item = dir_listbox.get(selection[0])
                
                current = path_var.get()
                if item == "../":
                    # Go up one level
                    new_path = os.path.dirname(current)
                    if not new_path:
                        new_path = "/"
                elif item.endswith("/"):
                    # Enter directory
                    item = item[:-1]  # Remove trailing slash
                    if current.endswith("/"):
                        new_path = current + item
                    else:
                        new_path = current + "/" + item
                else:
                    # It's a file, don't navigate
                    return
                    
                # Update path and refresh
                path_var.set(new_path.replace('\\', '/'))
                populate_listbox(new_path)
        
        # Handle select button
        def on_select():
            path = path_var.get()
            self.remote_folder_var.set(path)
            dialog.destroy()
        
        # Bind events
        dir_listbox.bind("<Double-1>", on_dir_double_click)
        select_button.config(command=on_select)
        
        # Initial population
        populate_listbox(current_path)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Make dialog modal
        dialog.wait_window()
    
    def on_transfer_direction_change(self, *args):
        """Handle transfer direction change"""
        # Update browse button states based on direction
        if self.transfer_direction.get() == "upload":
            # For upload, source is local and destination is remote
            self.update_status("Transfer direction set to Upload (Local → Remote)")
        else:
            # For download, source is remote and destination is local
            self.update_status("Transfer direction set to Download (Remote → Local)")
    
    def start_transfer(self):
        """Start file transfer process"""
        if not self.ssh_client or not self.sftp_client:
            messagebox.showerror("Error", "You must connect to SSH first")
            return
            
        # Get directory paths from the common folder selection
        local_dir = self.local_folder_var.get().strip()
        remote_dir = self.remote_folder_var.get().strip()
        
        if not local_dir:
            messagebox.showerror("Error", "Local folder must be specified")
            return
            
        if not remote_dir:
            messagebox.showerror("Error", "Remote folder must be specified")
            return
        
        # Transfer direction
        direction = self.transfer_direction.get()
        
        # Folder exclusions
        folder_exclusions = []
        if self.transfer_use_exclusions.get():
            # Get exclusions from the listbox
            folder_exclusions = list(self.transfer_exclusions_component["listbox"].get(0, tk.END))
            
        # Get compression options
        use_compression = self.use_compression.get()
        compression_level = self.compression_level.get()
        skip_compressed = self.skip_compressed.get()
        extract_archives = self.extract_archives.get()
            
        # Disable buttons during transfer
        self.transfer_button.config(state=tk.DISABLED)
        self.sync_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Reset stop flag
        self.stop_requested = False
        
        # Create and start transfer thread
        self.log_message(f"Starting file transfer between {local_dir} and {remote_dir} (direction: {direction})")
        self.sync_thread = threading.Thread(
            target=self.run_transfer,
            args=(local_dir, remote_dir, direction, folder_exclusions, 
                 use_compression, compression_level, skip_compressed, extract_archives)
        )
        self.sync_thread.daemon = True
        self.sync_thread.start()
    
    def run_transfer(self, local_dir, remote_dir, direction, folder_exclusions, 
                    use_compression, compression_level, skip_compressed, extract_archives):
        """Run the file transfer process"""
        try:
            # Create FolderSync instance
            folder_sync = FolderSync(callback=self.progress_callback, 
                                    max_workers=8)  # Adjust max_workers as needed
            
            # Set SSH and SFTP clients
            folder_sync.ssh = self.ssh_client
            folder_sync.sftp = self.sftp_client
            
            # Determine source and destination based on direction
            if direction == "upload":
                source_dir = local_dir
                dest_dir = remote_dir
            else:
                source_dir = remote_dir
                dest_dir = local_dir
            
            # Run transfer
            total_files, transferred_files, errors = folder_sync.transfer_directory(
                host=self.host_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get(),
                source_dir=source_dir,
                dest_dir=dest_dir,
                direction=direction,
                folder_exclusions=folder_exclusions,
                stop_check=lambda: self.stop_requested,
                use_compression=use_compression,
                compression_level=compression_level,
                skip_compressed=skip_compressed,
                extract_archives=extract_archives
            )
            
            if self.stop_requested:
                self.log_message("Transfer stopped by user")
                self.status_var.set("Transfer stopped")
            else:
                self.log_message(f"Transfer complete: {transferred_files} of {total_files} files transferred with {errors} errors")
                self.status_var.set("Transfer complete")
                
        except Exception as e:
            self.log_message(f"Error during transfer: {str(e)}")
            traceback.print_exc()
            self.status_var.set("Transfer failed")
        
        finally:
            # Re-enable buttons
            self.root.after(0, lambda: self.transfer_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.sync_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
    
    def start_sync(self):
        """Start the synchronization process"""
        if not self.ssh_client or not self.sftp_client:
            messagebox.showerror("Error", "You must connect to SSH first")
            return
            
        # Get local and remote directories
        local_dir = self.local_folder_var.get()
        remote_dir = self.remote_folder_var.get()
        
        if not local_dir or not remote_dir:
            messagebox.showerror("Error", "Local and remote directories must be specified")
            return
            
        # Get sync direction
        sync_direction = self.sync_direction.get()
        
        # Get extension filter
        if self.use_extension_filter.get():
            extension_filter = self.extensions_var.get().split(',')
            extension_filter = [ext.strip() for ext in extension_filter if ext.strip()]
            filter_mode = self.extension_filter_mode.get()
        else:
            extension_filter = None
            filter_mode = "include"
            
        # Log extension filter info
        if extension_filter:
            self.log_message(f"Using extension filter in {filter_mode} mode: {', '.join(extension_filter)}")
        
        # Get folder exclusions
        if self.use_folder_exclusions.get():
            folder_exclusions = list(self.folder_exclusions_component["listbox"].get(0, tk.END))
        else:
            folder_exclusions = None
            
        # Get comparison method
        use_content_hash = self.compare_method.get() == "content"
        
        # Get transfer method
        transfer_method = self.transfer_method.get()
        
        # Get use cache only option
        use_cache_only = self.use_cache_only_var.get()
        
        # If using cache only, make sure the cache files exist
        if use_cache_only:
            cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".synccache")
            local_cache = os.path.join(cache_dir, "local_cache.json")
            remote_cache = os.path.join(cache_dir, "remote_cache.json")
            
            # Check if both cache files exist
            if not os.path.exists(local_cache) or not os.path.exists(remote_cache):
                response = messagebox.askyesno(
                    "Missing Cache Files", 
                    "Cache files don't exist yet. Would you like to generate the cache first?\n\n"
                    "Click Yes to generate cache now.\n"
                    "Click No to continue without using cache (full scan)."
                )
                if response:
                    # Generate cache first, then sync will run after it completes
                    self.generate_cache()
                    return
                else:
                    # Continue without using cache
                    use_cache_only = False
                    self.log_message("Continuing with full scan since cache doesn't exist yet")
        
        # Disable UI elements
        self.sync_button.config(state=tk.DISABLED)
        self.transfer_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Reset stop flag
        self.stop_requested = False
        
        # Start sync in a thread
        self.sync_thread = threading.Thread(target=self.run_sync, args=(
            local_dir, remote_dir, sync_direction, extension_filter, filter_mode,
            folder_exclusions, use_content_hash, transfer_method, use_cache_only
        ))
        self.sync_thread.daemon = True
        self.sync_thread.start()
    
    def run_sync(self, local_dir, remote_dir, sync_direction, extension_filter, filter_mode,
                 folder_exclusions, use_content_hash, transfer_method, use_cache_only=False):
        """Run the synchronization process"""
        try:
            # Create FolderSync instance
            folder_sync = FolderSync(callback=self.progress_callback, 
                                    max_workers=8)  # Adjust max_workers as needed
            
            # Set SSH and SFTP clients
            folder_sync.ssh = self.ssh_client
            folder_sync.sftp = self.sftp_client
            
            # Setup cache directories and files
            cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".synccache")
            local_cache = os.path.join(cache_dir, "local_cache.json")
            remote_cache = os.path.join(cache_dir, "remote_cache.json")
            folder_sync.local_cache_file = local_cache
            folder_sync.remote_cache_file = remote_cache
            
            # Add debug button to force all files to sync regardless of comparison
            force_sync = False
            if hasattr(self, 'force_sync_var') and self.force_sync_var.get():
                force_sync = True
                self.log_message("Force sync enabled - will transfer all files regardless of comparison")
            
            # Log cache usage
            if use_cache_only:
                self.log_message("Using cache-only mode - only files in cache will be checked (faster)")
            
            # Run sync
            result = folder_sync.sync_directories(
                host=self.host_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get(),
                local_dir=local_dir,
                remote_dir=remote_dir,
                bidirectional=(sync_direction == "both"),
                sync_mode=sync_direction,
                extension_filters=extension_filter,
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                content_only_compare=use_content_hash,
                transfer_method=transfer_method,
                verbose_logging=True,
                force_sync=force_sync,
                use_cache_only=use_cache_only,
                stop_check=lambda: self.stop_requested
            )
            
            if self.stop_requested:
                self.log_message("Synchronization stopped by user")
                self.status_var.set("Synchronization stopped")
            else:
                self.log_message("Synchronization complete")
                self.status_var.set("Synchronization complete")
        
        except Exception as e:
            self.log_message(f"Error during synchronization: {str(e)}")
            traceback.print_exc()
            self.status_var.set("Synchronization failed")
        
        finally:
            # Re-enable buttons
            self.root.after(0, lambda: self.transfer_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.sync_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
    
    def stop_sync(self):
        """Signal the sync process to stop"""
        # Set the flag regardless of thread status
        self.stop_requested = True
        self.status_var.set("Stopping operation...")
        self.log_message("Stopping operation... Please wait for current file operations to complete.")
        
        # Display the stopping message prominently
        self.log_message("")
        self.log_message("========================================================")
        self.log_message("STOP REQUESTED - Operation will terminate after current file")
        self.log_message("========================================================")
        self.log_message("")
        
        # Disable the stop button to prevent multiple clicks
        self.stop_button.config(state=tk.DISABLED)
        
        # If the process is stuck in a remote operation, we schedule a UI update to check
        # if we need to force-terminate the thread after a timeout
        def check_if_still_running():
            if self.sync_thread and self.sync_thread.is_alive():
                self.log_message("Operation still running. Waiting for completion...")
                # Schedule another check after 10 seconds
                self.root.after(10000, check_if_still_running)
        
        # Start checking after 5 seconds
        self.root.after(5000, check_if_still_running)
    
    def save_settings(self):
        """Save current settings to file"""
        try:
            # Get folder exclusions from listboxes
            transfer_exclusions = list(self.transfer_exclusions_component["listbox"].get(0, tk.END))
            folder_exclusions = list(self.folder_exclusions_component["listbox"].get(0, tk.END))
            
            settings = {
                'host': self.host_var.get(),
                'port': self.port_var.get(),
                'username': self.username_var.get(),
                # Don't save the password for security
                'local_folder': self.local_folder_var.get(),
                'remote_folder': self.remote_folder_var.get(),
                'transfer_direction': self.transfer_direction.get(),
                'transfer_use_exclusions': self.transfer_use_exclusions.get(),
                'transfer_exclusions': transfer_exclusions,
                'sync_direction': self.sync_direction.get(),
                'use_extension_filter': self.use_extension_filter.get(),
                'extensions': self.extensions_var.get(),
                'extension_filter_mode': self.extension_filter_mode.get(),
                'use_folder_exclusions': self.use_folder_exclusions.get(),
                'folder_exclusions': folder_exclusions,
                'compare_method': self.compare_method.get(),
                'transfer_method': self.transfer_method.get(),
                'save_settings': self.save_settings_var.get(),
                'use_compression': self.use_compression.get(),
                'compression_level': self.compression_level.get(),
                'skip_compressed': self.skip_compressed.get(),
                'extract_archives': self.extract_archives.get(),
                'force_sync': self.force_sync_var.get(),
                'use_cache_only': self.use_cache_only_var.get()
            }
            
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
                
            self.log_message("Settings saved successfully")
        except Exception as e:
            self.log_message(f"Error saving settings: {str(e)}")
    
    def load_settings(self):
        """Load settings from file"""
        if not os.path.exists(self.settings_file):
            return
        
        try:
            with open(self.settings_file, 'r') as f:
                settings = json.load(f)
            
            # Set values from loaded settings
            self.host_var.set(settings.get('host', ''))
            self.port_var.set(settings.get('port', '22'))
            self.username_var.set(settings.get('username', ''))
            
            # Common folder selection
            self.local_folder_var.set(settings.get('local_folder', ''))
            self.remote_folder_var.set(settings.get('remote_folder', ''))
            
            # Transfer settings
            self.transfer_direction.set(settings.get('transfer_direction', 'upload'))
            self.transfer_use_exclusions.set(settings.get('transfer_use_exclusions', False))
            
            # Clear and populate transfer exclusions listbox
            self.transfer_exclusions_component["listbox"].delete(0, tk.END)
            transfer_exclusions = settings.get('transfer_exclusions', [])
            if isinstance(transfer_exclusions, str):
                # Handle old format (text with newlines)
                for item in transfer_exclusions.splitlines():
                    if item.strip():
                        self.transfer_exclusions_component["listbox"].insert(tk.END, item.strip())
            else:
                # Handle new format (list)
                for item in transfer_exclusions:
                    self.transfer_exclusions_component["listbox"].insert(tk.END, item)
            
            # Sync settings
            self.sync_direction.set(settings.get('sync_direction', 'both'))
            self.use_extension_filter.set(settings.get('use_extension_filter', False))
            self.extensions_var.set(settings.get('extensions', ''))
            self.extension_filter_mode.set(settings.get('extension_filter_mode', 'include'))
            self.use_folder_exclusions.set(settings.get('use_folder_exclusions', False))
            
            # Clear and populate folder exclusions listbox
            self.folder_exclusions_component["listbox"].delete(0, tk.END)
            folder_exclusions = settings.get('folder_exclusions', [])
            if isinstance(folder_exclusions, str):
                # Handle old format (text with newlines)
                for item in folder_exclusions.splitlines():
                    if item.strip():
                        self.folder_exclusions_component["listbox"].insert(tk.END, item.strip())
            else:
                # Handle new format (list)
                for item in folder_exclusions:
                    self.folder_exclusions_component["listbox"].insert(tk.END, item)
            
            # Set compare and transfer methods
            self.compare_method.set(settings.get('compare_method', 'quick'))
            self.transfer_method.set(settings.get('transfer_method', 'sftp'))
            
            # Other settings
            self.save_settings_var.set(settings.get('save_settings', True))
            self.use_compression.set(settings.get('use_compression', True))
            self.compression_level.set(settings.get('compression_level', 'balanced'))
            self.skip_compressed.set(settings.get('skip_compressed', True))
            self.extract_archives.set(settings.get('extract_archives', True))
            self.force_sync_var.set(settings.get('force_sync', False))
            self.use_cache_only_var.set(settings.get('use_cache_only', False))
            
            self.log_message("Settings loaded successfully")
        except Exception as e:
            self.log_message(f"Error loading settings: {str(e)}")
    
    def update_status(self, status_message):
        """Update the status message in the UI"""
        if status_message:
            self.status_var.set(status_message)
            self.root.update_idletasks()
    
    def progress_callback(self, status_message=None, progress=None, log_message=None):
        """Handle progress updates from the FolderSync class"""
        # Handle log messages
        if log_message:
            self.log_message(log_message)
        
        # Handle status messages
        if status_message:
            self.status_var.set(status_message)
        
        # Handle progress updates
        if progress is not None:
            self.progress_var.set(progress)
        
        # Update the UI - ensure it refreshes the display
        self.root.update_idletasks()
        
        # Process pending events to keep UI responsive
        self.root.update()
    
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
    
    def create_exclusion_list_frame(self, parent, label_text="Folder Exclusions"):
        """Create an improved folder exclusion list component with Listbox and buttons"""
        # Main container frame
        frame = ttk.Frame(parent)
        
        # Top section with label and entry
        top_frame = ttk.Frame(frame)
        top_frame.pack(fill=tk.X, pady=(0, 2))
        
        # Label
        ttk.Label(top_frame, text=label_text+":").pack(side=tk.LEFT, padx=(0, 5))
        
        # Entry for new items
        entry_var = tk.StringVar()
        entry = ttk.Entry(top_frame, textvariable=entry_var, width=20)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Add button
        add_button = ttk.Button(top_frame, text="Add", width=8)
        add_button.pack(side=tk.LEFT, padx=5)
        
        # Middle frame with Listbox and scrollbar
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.X, pady=2)
        
        # Listbox with scrollbar - REDUCED HEIGHT from 6 to 3
        listbox = tk.Listbox(list_frame, height=3, selectmode=tk.SINGLE)
        listbox.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)
        
        # Bottom frame with action buttons - more compact horizontal layout
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(2, 0))
        
        # Remove button
        remove_button = ttk.Button(button_frame, text="Remove", width=8)
        remove_button.pack(side=tk.LEFT, padx=2)
        
        # Clear all button
        clear_button = ttk.Button(button_frame, text="Clear", width=6)
        clear_button.pack(side=tk.LEFT, padx=2)
        
        # Example button
        example_button = ttk.Button(button_frame, text="Examples", width=8)
        example_button.pack(side=tk.RIGHT, padx=2)
        
        # Define helper functions for this component
        def add_item():
            item = entry_var.get().strip()
            if item and item not in listbox.get(0, tk.END):
                listbox.insert(tk.END, item)
                entry_var.set("")  # Clear entry after adding
        
        def remove_item():
            selected = listbox.curselection()
            if selected:
                listbox.delete(selected[0])
        
        def clear_all():
            listbox.delete(0, tk.END)
        
        def add_examples():
            examples = ["tmp", ".git", "logs", "build", "dist", "__pycache__", "node_modules"]
            for example in examples:
                if example not in listbox.get(0, tk.END):
                    listbox.insert(tk.END, example)
        
        # Bind functions to buttons
        add_button.config(command=add_item)
        remove_button.config(command=remove_item)
        clear_button.config(command=clear_all)
        example_button.config(command=add_examples)
        
        # Bind Enter key to add_item
        entry.bind("<Return>", lambda event: add_item())
        
        # Create a dict with all component references
        component = {
            "frame": frame,
            "listbox": listbox,
            "entry": entry,
            "entry_var": entry_var,
            "add_item": add_item,
            "remove_item": remove_item,
            "clear_all": clear_all
        }
        
        return component

    def generate_cache(self):
        """Generate cache for faster synchronization"""
        # Check if we have an SSH connection
        if not hasattr(self, 'ssh_client') or not self.ssh_client:
            self.log_message("ERROR: No SSH connection. Please connect first.")
            messagebox.showerror("Error", "No SSH connection. Please connect first.")
            return

        # Check if we have an SFTP connection
        if not hasattr(self, 'sftp_client') or not self.sftp_client:
            self.log_message("ERROR: No SFTP connection. Please connect first.")
            messagebox.showerror("Error", "No SFTP connection. Please connect first.")
            return

        # Get local and remote directories
        local_dir = self.local_folder_var.get().strip()
        remote_dir = self.remote_folder_var.get().strip()

        if not local_dir or not remote_dir:
            self.log_message("ERROR: Local and remote directories must be specified.")
            messagebox.showerror("Error", "Local and remote directories must be specified.")
            return

        # Get extension filters
        extension_filter = []
        extension_text = self.extensions_var.get().strip()
        if extension_text:
            extension_filter = [ext.strip() for ext in extension_text.split(',')]

        filter_mode = self.extension_filter_mode.get()
        
        # Log extension filter info
        if extension_filter:
            self.log_message(f"Using extension filter in {filter_mode} mode: {', '.join(extension_filter)}")
        
        # Get folder exclusions
        folder_exclusions = []
        if self.use_folder_exclusions.get():
            folder_exclusions = list(self.folder_exclusions_component["listbox"].get(0, tk.END))

        # Update UI state
        self.sync_button.config(state=tk.DISABLED)
        self.transfer_button.config(state=tk.DISABLED)
        self.connect_button.config(state=tk.DISABLED)
        self.generate_cache_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_requested = False

        # Start a new thread for cache generation
        self.sync_thread = threading.Thread(
            target=self._generate_cache_thread,
            args=(local_dir, remote_dir, extension_filter, filter_mode, folder_exclusions)
        )
        self.sync_thread.daemon = True
        self.sync_thread.start()
    
    def _generate_cache_thread(self, local_dir, remote_dir, extension_filter, filter_mode, folder_exclusions):
        """Thread function to generate cache for local and remote files"""
        try:
            self.status_var.set("Generating cache...")
            self.log_message(f"Starting cache generation for local and remote files")
            self.log_message(f"Local directory: {local_dir}")
            self.log_message(f"Remote directory: {remote_dir}")
            self.log_message(f"Note: You can click the Stop Operation button at any time to abort")

            # Create sync instance with more workers for faster processing but not too many to overload
            max_workers = min(8, os.cpu_count() or 4)
            self.log_message(f"Using {max_workers} parallel workers for hash calculation")
            folder_sync = FolderSync(callback=self.progress_callback, max_workers=max_workers)
            
            # Set SSH and SFTP clients
            folder_sync.ssh = self.ssh_client
            folder_sync.sftp = self.sftp_client

            # Setup cache directories if needed
            cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".synccache")
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
                self.log_message(f"Created cache directory: {cache_dir}")
            
            # Set cache files
            local_cache = os.path.join(cache_dir, "local_cache.json")
            remote_cache = os.path.join(cache_dir, "remote_cache.json")
            folder_sync.local_cache_file = local_cache
            folder_sync.remote_cache_file = remote_cache

            # Scan local files
            self.status_var.set("Scanning local files...")
            self.log_message("Scanning local files and calculating hashes...")
            self.progress_callback(status_message="Scanning local files...", progress=0)

            # Start time tracking for performance reporting
            local_start_time = time.time()
            
            local_files = folder_sync.list_local_files(
                local_dir, 
                extension_filters=extension_filter,
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                calculate_hashes=True,
                stop_check=lambda: self.stop_requested
            )

            local_duration = time.time() - local_start_time
            
            if self.stop_requested:
                self.status_var.set("Cache generation stopped by user.")
                self.log_message("Cache generation stopped by user.")
                self._reset_ui_after_sync()
                return

            local_file_count = len(local_files)
            self.log_message(f"Found {local_file_count} files in local directory")
            self.log_message(f"Local processing took {local_duration:.1f} seconds")
            
            # Save local metadata
            self.log_message("Saving local metadata...")
            folder_sync.save_local_metadata(folder_sync.local_metadata)
            self.log_message("Local metadata saved successfully")

            # Scan remote files
            self.status_var.set("Scanning remote files...")
            self.log_message("Scanning remote files and calculating hashes...")
            self.log_message("This may take some time for large files. You can stop the process at any time.")
            self.progress_callback(status_message="Scanning remote files...", progress=50)

            # Start time tracking for performance reporting
            remote_start_time = time.time()
            
            # Check if SSH connection is still valid
            try:
                # Try a simple command to test connection
                self.ssh_client.exec_command("echo test", timeout=5)
            except Exception as e:
                self.log_message(f"SSH connection error, attempting to reconnect: {str(e)}")
                try:
                    # Reconnect if needed
                    self.ssh_client.close()
                    self.sftp_client.close()
                    self.ssh_client = paramiko.SSHClient()
                    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.ssh_client.connect(
                        hostname=self.host_var.get(),
                        port=int(self.port_var.get()),
                        username=self.username_var.get(),
                        password=self.password_var.get()
                    )
                    self.sftp_client = self.ssh_client.open_sftp()
                    folder_sync.ssh = self.ssh_client
                    folder_sync.sftp = self.sftp_client
                    self.log_message("SSH connection re-established successfully")
                except Exception as reconnect_error:
                    self.log_message(f"Failed to reconnect: {str(reconnect_error)}")
                    self.status_var.set("Cache generation failed - connection error")
                    self._reset_ui_after_sync()
                    return

            # Create a watchdog to detect if the process appears stuck
            last_activity_time = time.time()
            
            def activity_watchdog():
                nonlocal last_activity_time
                if not self.stop_requested and time.time() - last_activity_time > 120:  # 2 minutes with no updates
                    self.log_message("WARNING: No progress detected for 2 minutes. The process may be stuck.")
                    self.log_message("You can click the Stop Operation button to abort.")
                    # Schedule another check in 60 seconds
                    self.root.after(60000, activity_watchdog)
                elif not self.stop_requested:
                    # Schedule another check in 30 seconds
                    self.root.after(30000, activity_watchdog)
            
            # Start the watchdog
            self.root.after(30000, activity_watchdog)
            
            # Update the last activity time whenever we log something
            original_log = folder_sync.log
            def log_with_activity(message):
                nonlocal last_activity_time
                last_activity_time = time.time()
                original_log(message)
            folder_sync.log = log_with_activity

            # Run the remote file scanning with improved monitoring
            remote_files = folder_sync.list_remote_files(
                self.sftp_client,
                remote_dir, 
                extension_filters=extension_filter,
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                calculate_hashes=True,
                stop_check=lambda: self.stop_requested
            )

            remote_duration = time.time() - remote_start_time
            
            if self.stop_requested:
                self.status_var.set("Cache generation stopped by user.")
                self.log_message("Cache generation stopped by user.")
                self._reset_ui_after_sync()
            return
            
            remote_file_count = len(remote_files)
            self.log_message(f"Found {remote_file_count} files in remote directory")
            self.log_message(f"Remote processing took {remote_duration:.1f} seconds")
            
            # Save remote metadata
            self.log_message("Saving remote metadata...")
            folder_sync.save_remote_metadata(folder_sync.remote_metadata)
            self.log_message("Remote metadata saved successfully")

            # Update UI with completion message
            self.status_var.set("Cache generation complete")
            self.log_message("Cache generation complete")
            self.log_message(f"Local files: {local_file_count}, Remote files: {remote_file_count}")
            self.log_message(f"Total processing time: {(local_duration + remote_duration):.1f} seconds")
            self.progress_callback(status_message="Cache generation complete", progress=100)
            
        except Exception as e:
            self.status_var.set(f"Error during cache generation: {str(e)}")
            self.log_message(f"ERROR: {str(e)}")
            traceback.print_exc()
        finally:
            self._reset_ui_after_sync()

    def _reset_ui_after_sync(self):
        """Reset UI elements after a sync operation"""
        self.root.after(0, lambda: self.transfer_button.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.sync_button.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.generate_cache_button.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.connect_button.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))


def main():
    root = tk.Tk()
    app = FolderSyncApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()