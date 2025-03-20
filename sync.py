#!/usr/bin/env python3
import os
import sys
import paramiko
import hashlib
import stat
import argparse
from datetime import datetime
import getpass
import traceback
from stat import S_ISDIR
import fnmatch
import time
import json
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import partial

class FolderSync:
    def __init__(self, callback=None, local_cache_file=None, remote_cache_file=None, max_workers=None):
        """
        Initialize the folder sync with an optional callback for progress updates
        
        callback: function(status_message, progress_percentage, log_message)
        local_cache_file: path to file for caching local file metadata
        remote_cache_file: path to file for caching remote file metadata
        max_workers: maximum number of worker processes/threads to use (None = auto)
        """
        self.callback = callback
        self.total_files = 0
        self.current_file = 0
        
        # Determine the number of workers to use (default to CPU count)
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.log(f"Using up to {self.max_workers} worker processes for file comparison")
        
        # Metadata cache files
        self.local_cache_file = local_cache_file
        self.remote_cache_file = remote_cache_file
        
        # Metadata dictionaries (loaded from cache)
        self.local_metadata = {}
        self.remote_metadata = {}
    
    def log(self, message):
        """Log a message using the callback if available"""
        if self.callback:
            self.callback(log_message=message)
        else:
            print(message)
    
    def update_status(self, status):
        """Update status message using the callback if available"""
        if self.callback:
            self.callback(status_message=status)
        else:
            print(status)
    
    def update_progress(self, progress):
        """Update progress using the callback if available"""
        if self.callback:
            self.callback(progress=progress)
    
    def get_file_hash(self, file_path):
        """Calculate MD5 hash for a file"""
        hash_md5 = hashlib.md5()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for {file_path}: {str(e)}")
            return None
    
    def get_remote_file_hash(self, sftp, file_path):
        """Calculate MD5 hash for a remote file"""
        hash_md5 = hashlib.md5()
        
        try:
            with sftp.open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for remote {file_path}: {str(e)}")
            return None
    
    def calculate_hash_batch(self, files_to_hash, is_remote=False, sftp=None):
        """Calculate hashes for a batch of files and return the results"""
        results = {}
        for rel_path, info in files_to_hash.items():
            if is_remote:
                hash_value = self.get_remote_file_hash(sftp, info['path'])
            else:
                hash_value = self.get_file_hash(info['path'])
                
            results[rel_path] = hash_value
            
        return results
    
    def calculate_hashes_parallel(self, files_dict, is_remote=False, sftp=None):
        """Calculate hashes for multiple files in parallel using multiple cores"""
        if not files_dict:
            return {}
            
        # Identify files that need hashes calculated
        files_to_hash = {rel_path: info for rel_path, info in files_dict.items() 
                         if info['hash'] is None}
        
        if not files_to_hash:
            return {}
            
        self.log(f"Calculating hashes for {len(files_to_hash)} files using {self.max_workers} workers")
        
        # Divide work into batches for parallel processing
        batch_size = max(1, len(files_to_hash) // (self.max_workers * 2))
        batches = []
        current_batch = {}
        count = 0
        
        for rel_path, info in files_to_hash.items():
            current_batch[rel_path] = info
            count += 1
            
            if count >= batch_size:
                batches.append(current_batch)
                current_batch = {}
                count = 0
                
        if current_batch:
            batches.append(current_batch)
        
        results = {}
        
        # Process batches in parallel using ThreadPoolExecutor for both local and remote files
        # This avoids pickling errors with Tkinter objects
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            if is_remote:
                # Create a partial function with the sftp parameter fixed
                batch_func = partial(self.calculate_hash_batch, is_remote=True, sftp=sftp)
                future_to_batch = {executor.submit(batch_func, batch): batch for batch in batches}
            else:
                # For local files, also use ThreadPoolExecutor to avoid pickling errors
                future_to_batch = {executor.submit(self.calculate_hash_batch, batch, False, None): batch 
                                 for batch in batches}
            
            for future in as_completed(future_to_batch):
                try:
                    batch_results = future.result()
                    results.update(batch_results)
                except Exception as e:
                    self.log(f"Error in hash calculation batch: {str(e)}")
        
        # Update the original dictionary with the calculated hashes
        for rel_path, hash_value in results.items():
            files_dict[rel_path]['hash'] = hash_value
            
        return results
    
    def load_local_metadata(self):
        """Load local file metadata from cache file"""
        if not self.local_cache_file or not os.path.exists(self.local_cache_file):
            return {}
        
        try:
            with open(self.local_cache_file, 'r') as f:
                metadata = json.load(f)
            self.log(f"Loaded metadata for {len(metadata)} local files from cache")
            return metadata
        except Exception as e:
            self.log(f"Error loading local metadata cache: {str(e)}")
            return {}
    
    def save_local_metadata(self, metadata):
        """Save local file metadata to cache file"""
        if not self.local_cache_file:
            return False
        
        try:
            # Create directory if it doesn't exist
            cache_dir = os.path.dirname(self.local_cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
                
            with open(self.local_cache_file, 'w') as f:
                json.dump(metadata, f)
            self.log(f"Saved metadata for {len(metadata)} local files to cache")
            return True
        except Exception as e:
            self.log(f"Error saving local metadata cache: {str(e)}")
            return False
    
    def load_remote_metadata(self):
        """Load remote file metadata from cache file"""
        if not self.remote_cache_file or not os.path.exists(self.remote_cache_file):
            return {}
        
        try:
            with open(self.remote_cache_file, 'r') as f:
                metadata = json.load(f)
            self.log(f"Loaded metadata for {len(metadata)} remote files from cache")
            return metadata
        except Exception as e:
            self.log(f"Error loading remote metadata cache: {str(e)}")
            return {}
    
    def save_remote_metadata(self, metadata):
        """Save remote file metadata to cache file"""
        if not self.remote_cache_file:
            return False
        
        try:
            # Create directory if it doesn't exist
            cache_dir = os.path.dirname(self.remote_cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
                
            with open(self.remote_cache_file, 'w') as f:
                json.dump(metadata, f)
            self.log(f"Saved metadata for {len(metadata)} remote files to cache")
            return True
        except Exception as e:
            self.log(f"Error saving remote metadata cache: {str(e)}")
            return False
    
    def list_local_files(self, local_dir, ignore_patterns=None, extension_filters=None, filter_mode="include", folder_exclusions=None, calculate_hashes=False):
        """List all files in the local directory with their MD5 hashes"""
        if ignore_patterns is None:
            ignore_patterns = []
            
        if folder_exclusions is None:
            folder_exclusions = []
            
        result = {}
        
        # Try to load from cache first
        cached_metadata = self.load_local_metadata()
        
        try:
            if not os.path.exists(local_dir):
                self.log(f"Local directory {local_dir} does not exist")
                return {}
            
            # First, check which files still exist and have the same metadata
            cached_files_still_valid = set()
            
            for rel_path, cached_info in cached_metadata.items():
                full_path = os.path.join(local_dir, rel_path.replace('/', os.path.sep))
                
                # Check if file still exists
                if not os.path.exists(full_path):
                    continue
                
                # Check if folder should be excluded
                should_exclude = False
                file_dir = os.path.dirname(rel_path)
                
                for exclusion in folder_exclusions:
                    # Check if the file is in an excluded folder or subfolder
                    if file_dir == exclusion or file_dir.startswith(exclusion + '/'):
                        should_exclude = True
                        break
                
                if should_exclude:
                    continue
                
                # Check if extension filter applies
                if extension_filters:
                    file_matches_filter = False
                    for pattern in extension_filters:
                        if fnmatch.fnmatch(os.path.basename(rel_path), pattern):
                            file_matches_filter = True
                            break
                    
                    # Skip based on filter mode
                    if (filter_mode == "include" and not file_matches_filter) or \
                       (filter_mode == "exclude" and file_matches_filter):
                        continue
                
                # Check if file has been modified
                current_size = os.path.getsize(full_path)
                current_mtime = os.path.getmtime(full_path)
                
                # If size and mtime match exactly, keep the cached info
                if abs(cached_info['size'] - current_size) < 2 and abs(cached_info['mtime'] - current_mtime) < 2:
                    result[rel_path] = cached_info.copy()
                    cached_files_still_valid.add(rel_path)
                else:
                    # File changed, need to update info but can reuse path
                    result[rel_path] = {
                        'path': full_path,
                        'hash': None,  # Hash is invalidated
                        'size': current_size,
                        'mtime': current_mtime
                    }
                    cached_files_still_valid.add(rel_path)
            
            # Now scan for new files
            for root, dirs, files in os.walk(local_dir):
                # Remove excluded folders from dirs to prevent walking them
                dirs_to_remove = []
                rel_root = os.path.relpath(root, local_dir).replace('\\', '/')
                
                if rel_root == '.':
                    rel_root = ''
                    
                for i, d in enumerate(dirs):
                    # Check if directory should be excluded
                    for exclusion in folder_exclusions:
                        dir_path = os.path.join(rel_root, d).replace('\\', '/')
                        if dir_path == exclusion or dir_path.startswith(exclusion + '/') or d == exclusion:
                            dirs_to_remove.append(i)
                            break
                            
                    # Also check if directory matches any ignore patterns
                    for pattern in ignore_patterns:
                        if fnmatch.fnmatch(d, pattern):
                            if i not in dirs_to_remove:
                                dirs_to_remove.append(i)
                            break
                
                # Remove excluded directories from the list (in reverse order to maintain indices)
                for i in sorted(dirs_to_remove, reverse=True):
                    del dirs[i]
                
                # Process files
                for file in files:
                    # Check if file should be ignored
                    skip_file = False
                    for pattern in ignore_patterns:
                        if fnmatch.fnmatch(file, pattern):
                            skip_file = True
                            break
                    
                    if skip_file:
                        continue
                    
                    # Apply extension filtering if provided
                    if extension_filters:
                        file_matches_filter = False
                        for pattern in extension_filters:
                            if fnmatch.fnmatch(file, pattern):
                                file_matches_filter = True
                                break
                        
                        # Skip based on filter mode
                        if (filter_mode == "include" and not file_matches_filter) or \
                           (filter_mode == "exclude" and file_matches_filter):
                            continue
                        
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, local_dir)
                    # Convert Windows path separators to Unix
                    rel_path = rel_path.replace('\\', '/')
                    
                    # If we already processed this file from cache, skip it
                    if rel_path in cached_files_still_valid:
                        continue
                    
                    # This is a new file, add it to the result
                    result[rel_path] = {
                        'path': full_path,
                        'hash': None,  # We'll calculate hashes later
                        'size': os.path.getsize(full_path),
                        'mtime': os.path.getmtime(full_path)
                    }
            
            self.log(f"Found {len(result)} files in local directory (of which {len(cached_files_still_valid)} from cache)")
            
            # Calculate hashes in parallel if requested
            if calculate_hashes:
                self.log("Pre-calculating hashes for local files...")
                self.calculate_hashes_parallel(result, is_remote=False)
            
            # Store the local metadata for later saving
            self.local_metadata = result
            
            return result
            
        except Exception as e:
            self.log(f"Error scanning local directory: {str(e)}")
            return {}
    
    def list_remote_files(self, sftp, remote_dir, ignore_patterns=None, extension_filters=None, filter_mode="include", folder_exclusions=None, calculate_hashes=False):
        """List all files in the remote directory with their MD5 hashes"""
        if ignore_patterns is None:
            ignore_patterns = []
            
        if folder_exclusions is None:
            folder_exclusions = []
            
        result = {}
        
        # Try to load from cache first
        cached_metadata = self.load_remote_metadata()
        
        try:
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                self.log(f"Remote directory {remote_dir} does not exist")
                return {}
            
            # We'll use this to track files that still exist on the remote
            files_found = set()
            
            def scan_remote_dir(sftp, path, base_path, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes):
                try:
                    entries = sftp.listdir_attr(path)
                except Exception as e:
                    self.log(f"Error listing directory {path}: {str(e)}")
                    return
                    
                for entry in entries:
                    name = entry.filename
                    
                    # Check if file/directory should be ignored
                    skip_entry = False
                    for pattern in ignore_patterns:
                        if fnmatch.fnmatch(name, pattern):
                            skip_entry = True
                            break
                    
                    if skip_entry:
                        continue
                        
                    full_path = f"{path}/{name}" if path != "/" else f"/{name}"
                    rel_path = full_path[len(base_path):].lstrip('/')
                    
                    if S_ISDIR(entry.st_mode):
                        # Check if directory should be excluded
                        should_exclude = False
                        for exclusion in folder_exclusions:
                            if rel_path == exclusion or rel_path.startswith(exclusion + '/'):
                                should_exclude = True
                                break
                                
                        if should_exclude:
                            continue
                            
                        scan_remote_dir(sftp, full_path, base_path, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes)
                    else:
                        # Check if parent directory should be excluded
                        dir_path = os.path.dirname(rel_path)
                        should_exclude = False
                        for exclusion in folder_exclusions:
                            if dir_path == exclusion or dir_path.startswith(exclusion + '/'):
                                should_exclude = True
                                break
                                
                        if should_exclude:
                            continue
                            
                        # Apply extension filtering if provided
                        if extension_filters:
                            file_matches_filter = False
                            for pattern in extension_filters:
                                if fnmatch.fnmatch(name, pattern):
                                    file_matches_filter = True
                                    break
                            
                            # Skip based on filter mode
                            if (filter_mode == "include" and not file_matches_filter) or \
                               (filter_mode == "exclude" and file_matches_filter):
                                continue
                                
                        files_found.add(rel_path)
                        
                        # Check if we have cached metadata for this file
                        if rel_path in cached_metadata:
                            cached_info = cached_metadata[rel_path]
                            
                            # If size and mtime match, use cached info
                            if abs(cached_info['size'] - entry.st_size) < 2 and abs(cached_info['mtime'] - entry.st_mtime) < 2:
                                result[rel_path] = cached_info.copy()
                                continue
                        
                        # File is new or has changed, add with fresh metadata
                        result[rel_path] = {
                            'path': full_path,
                            'hash': None,  # We'll calculate hashes later
                            'size': entry.st_size,
                            'mtime': entry.st_mtime
                        }
            
            # Ensure remote_dir ends with '/'
            if not remote_dir.endswith('/'):
                remote_dir += '/'
                
            # Start recursive scan
            scan_remote_dir(sftp, remote_dir, remote_dir, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes)
            
            cached_files_used = len(set(result.keys()) & set(cached_metadata.keys()))
            new_files_found = len(result) - cached_files_used
            
            self.log(f"Found {len(result)} files in remote directory (of which {cached_files_used} from cache, {new_files_found} new)")
            
            # Calculate hashes in parallel if requested
            if calculate_hashes:
                self.log("Pre-calculating hashes for remote files...")
                self.calculate_hashes_parallel(result, is_remote=True, sftp=sftp)
            
            # Store the remote metadata for later saving
            self.remote_metadata = result
            
            return result
            
        except Exception as e:
            self.log(f"Error scanning remote directory: {str(e)}")
            return {}
    
    def sync_with_existing_connection(self, ssh_client, sftp_client, local_dir, remote_dir, 
                                     bidirectional=True, sync_mode="both", 
                                     extension_filters=None, filter_mode="include",
                                     stop_check=None, folder_exclusions=None, content_only_compare=False):
        """Sync files using existing SSH and SFTP connections"""
        self.update_status("Starting synchronization with existing connection...")
        
        try:
            # Normalize paths
            local_dir = os.path.normpath(local_dir)
            if not remote_dir.endswith('/'):
                remote_dir += '/'
                
            # Show filter status if enabled
            if extension_filters:
                self.log(f"Filtering files with {filter_mode} mode for extensions: {', '.join(extension_filters)}")
                
            # Show folder exclusions if enabled
            if folder_exclusions:
                self.log(f"Excluding folders: {', '.join(folder_exclusions)}")
                
            # Show comparison method
            if content_only_compare:
                self.log("Using content-only comparison (MD5 hash)")
            else:
                self.log("Using quick comparison (size and modification time)")
                
            # Scan directories
            self.update_status("Scanning local directory...")
            local_files = self.list_local_files(
                local_dir, 
                extension_filters=extension_filters, 
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                calculate_hashes=content_only_compare
            )
            
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Synchronization stopped before scanning remote directory")
                return False
                
            self.update_status("Scanning remote directory...")
            remote_files = self.list_remote_files(
                sftp_client, 
                remote_dir, 
                extension_filters=extension_filters, 
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                calculate_hashes=content_only_compare
            )
            
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Synchronization stopped after scanning directories")
                return False
            
            # Begin sync process based on sync_mode
            sync_success = True
            
            if sync_mode in ["both", "to_remote"] and local_files is not None:
                to_remote_success = self._sync_local_to_remote(
                    ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, 
                    stop_check, content_only_compare
                )
                sync_success = sync_success and to_remote_success
                
                # Check if stop was requested
                if stop_check and stop_check():
                    return False
                
            if sync_mode in ["both", "to_local"] and remote_files is not None:
                to_local_success = self._sync_remote_to_local(
                    ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, 
                    stop_check, content_only_compare
                )
                sync_success = sync_success and to_local_success
            
            # Final stop check
            if stop_check and stop_check():
                return False
            
            # Save metadata cache if sync was successful
            if sync_success:
                self.save_local_metadata(self.local_metadata)
                self.save_remote_metadata(self.remote_metadata)
                
            self.update_status("Synchronization completed")
            self.update_progress(100)
            
        except Exception as e:
            self.log(f"Error during synchronization: {str(e)}")
            self.update_status("Synchronization failed")
            return False
            
        return True
    
    def sync_directories(self, host, port, username, password, local_dir, remote_dir, 
                        bidirectional=True, sync_mode="both", 
                        extension_filters=None, filter_mode="include",
                        stop_check=None, folder_exclusions=None, content_only_compare=False):
        """Sync files between local and remote directories"""
        self.update_status(f"Connecting to {host}...")
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to SSH server
            client.connect(hostname=host, port=port, username=username, password=password)
            self.log(f"Connected to {host}")
            
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Synchronization stopped after connection")
                return False
            
            # Open SFTP session
            sftp = client.open_sftp()
            
            # Perform sync using the connection
            result = self.sync_with_existing_connection(
                client, sftp, local_dir, remote_dir, bidirectional, sync_mode,
                extension_filters, filter_mode, stop_check, folder_exclusions, content_only_compare
            )
            
            # Close connections
            sftp.close()
            client.close()
            
            return result
            
        except Exception as e:
            self.log(f"Error connecting to server: {str(e)}")
            self.update_status("Connection failed")
            return False
    
    def _sync_local_to_remote(self, ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, stop_check=None, content_only_compare=False):
        """Sync files from local to remote"""
        self.update_status("Syncing local files to remote...")
        
        # Calculate total files for progress tracking
        self.total_files = len(local_files)
        self.current_file = 0
        
        # If we need content comparison and have many files, pre-calculate hashes in parallel
        if content_only_compare:
            # We prioritize calculating hashes for files without cached hashes
            files_needing_hash = {rel_path: info for rel_path, info in local_files.items() 
                                 if rel_path in remote_files and info['hash'] is None}
            
            remote_files_needing_hash = {rel_path: remote_files[rel_path] for rel_path in files_needing_hash 
                                       if remote_files[rel_path]['hash'] is None}
            
            if files_needing_hash:
                self.log(f"Pre-calculating hashes for {len(files_needing_hash)} local files to compare...")
                # Calculate local hashes in parallel
                self.calculate_hashes_parallel(files_needing_hash, is_remote=False)
                
            if remote_files_needing_hash:
                self.log(f"Pre-calculating hashes for {len(remote_files_needing_hash)} remote files to compare...")
                # Calculate remote hashes in parallel
                self.calculate_hashes_parallel(remote_files_needing_hash, is_remote=True, sftp=sftp_client)
        
        # Process each local file
        for rel_path, local_info in local_files.items():
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Local to remote sync stopped")
                return False
                
            self.current_file += 1
            progress = (self.current_file / self.total_files) * 100 if self.total_files > 0 else 0
            self.update_progress(progress / 2)  # First half of the progress bar
            
            remote_path = os.path.join(remote_dir, rel_path).replace('\\', '/')
            
            # Check if file exists on remote
            if rel_path in remote_files:
                remote_info = remote_files[rel_path]
                
                # Determine if files are the same
                files_are_same = False
                
                if content_only_compare:
                    # For content-only compare, we use only MD5 hashes
                    # Calculate hashes if not already done
                    if local_info['hash'] is None:
                        local_info['hash'] = self.get_file_hash(local_info['path'])
                    
                    if remote_info['hash'] is None:
                        remote_info['hash'] = self.get_remote_file_hash(sftp_client, remote_info['path'])
                    
                    # Compare only hashes
                    files_are_same = local_info['hash'] and remote_info['hash'] and local_info['hash'] == remote_info['hash']
                else:
                    # Use quick comparison first
                    size_time_same = abs(local_info['size'] - remote_info['size']) < 10 and abs(local_info['mtime'] - remote_info['mtime']) < 5
                    
                    if size_time_same:
                        # Size and time match, assume they're the same
                        files_are_same = True
                    else:
                        # Calculate hashes for comparison
                        if local_info['hash'] is None:
                            local_info['hash'] = self.get_file_hash(local_info['path'])
                        
                        if remote_info['hash'] is None:
                            remote_info['hash'] = self.get_remote_file_hash(sftp_client, remote_info['path'])
                        
                        # Compare hashes
                        files_are_same = local_info['hash'] and remote_info['hash'] and local_info['hash'] == remote_info['hash']
                
                if files_are_same:
                    self.log(f"Skipping identical file: {rel_path}")
                    continue
                
                self.log(f"Updating remote file: {rel_path}")
            else:
                self.log(f"Copying new file to remote: {rel_path}")
                
                # Create remote directories if needed
                remote_dir_path = os.path.dirname(remote_path)
                if remote_dir_path:
                    try:
                        sftp_client.stat(remote_dir_path)
                    except FileNotFoundError:
                        # Create directory structure
                        current_dir = ""
                        for part in remote_dir_path.split('/'):
                            if not part:
                                continue
                            current_dir += '/' + part
                            try:
                                sftp_client.stat(current_dir)
                            except FileNotFoundError:
                                sftp_client.mkdir(current_dir)
            
            # Copy file to remote
            try:
                sftp_client.put(local_info['path'], remote_path)
                # Preserve modification time
                sftp_client.utime(remote_path, (local_info['mtime'], local_info['mtime']))
            except Exception as e:
                self.log(f"Error copying {rel_path} to remote: {str(e)}")
                
            # Periodic stop check during file transfers
            if stop_check and stop_check() and self.current_file % 5 == 0:
                self.log("Local to remote sync stopped during transfer")
                return False
        
        return True
    
    def _sync_remote_to_local(self, ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, stop_check=None, content_only_compare=False):
        """Sync files from remote to local"""
        if not remote_files:
            self.log("No remote files to sync")
            return True
            
        self.update_status("Syncing remote files to local...")
        
        # Calculate total files for progress tracking
        self.total_files = len(remote_files)
        self.current_file = 0
        
        # If we need content comparison and have many files, pre-calculate hashes in parallel
        if content_only_compare:
            # We prioritize calculating hashes for files without cached hashes
            files_needing_hash = {rel_path: info for rel_path, info in remote_files.items() 
                                 if rel_path in local_files and info['hash'] is None}
            
            local_files_needing_hash = {rel_path: local_files[rel_path] for rel_path in files_needing_hash 
                                       if local_files[rel_path]['hash'] is None}
            
            if files_needing_hash:
                self.log(f"Pre-calculating hashes for {len(files_needing_hash)} remote files to compare...")
                # Calculate remote hashes in parallel
                self.calculate_hashes_parallel(files_needing_hash, is_remote=True, sftp=sftp_client)
                
            if local_files_needing_hash:
                self.log(f"Pre-calculating hashes for {len(local_files_needing_hash)} local files to compare...")
                # Calculate local hashes in parallel
                self.calculate_hashes_parallel(local_files_needing_hash, is_remote=False)
        
        # Process each remote file
        for rel_path, remote_info in remote_files.items():
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Remote to local sync stopped")
                return False
                
            self.current_file += 1
            progress = 50 + ((self.current_file / self.total_files) * 100 if self.total_files > 0 else 0) / 2  # Second half of progress
            self.update_progress(progress)
            
            local_path = os.path.normpath(os.path.join(local_dir, rel_path))
            
            # Check if file exists locally
            if rel_path in local_files:
                local_info = local_files[rel_path]
                
                # Determine if files are the same
                files_are_same = False
                
                if content_only_compare:
                    # For content-only compare, we use only MD5 hashes
                    # Calculate hashes if not already done
                    if local_info['hash'] is None:
                        local_info['hash'] = self.get_file_hash(local_info['path'])
                    
                    if remote_info['hash'] is None:
                        remote_info['hash'] = self.get_remote_file_hash(sftp_client, remote_info['path'])
                    
                    # Compare only hashes
                    files_are_same = local_info['hash'] and remote_info['hash'] and local_info['hash'] == remote_info['hash']
                else:
                    # Use quick comparison first
                    size_time_same = abs(local_info['size'] - remote_info['size']) < 10 and abs(local_info['mtime'] - remote_info['mtime']) < 5
                    
                    if size_time_same:
                        # Size and time match, assume they're the same
                        files_are_same = True
                    else:
                        # Calculate hashes for comparison
                        if local_info['hash'] is None:
                            local_info['hash'] = self.get_file_hash(local_info['path'])
                        
                        if remote_info['hash'] is None:
                            remote_info['hash'] = self.get_remote_file_hash(sftp_client, remote_info['path'])
                        
                        # Compare hashes
                        files_are_same = local_info['hash'] and remote_info['hash'] and local_info['hash'] == remote_info['hash']
                
                if files_are_same:
                    self.log(f"Skipping identical file: {rel_path}")
                    continue
                
                self.log(f"Updating local file: {rel_path}")
            else:
                self.log(f"Copying new file to local: {rel_path}")
                
                # Create local directories if needed
                local_dir_path = os.path.dirname(local_path)
                if local_dir_path and not os.path.exists(local_dir_path):
                    os.makedirs(local_dir_path)
            
            # Copy file to local
            try:
                sftp_client.get(remote_info['path'], local_path)
                # Preserve modification time
                os.utime(local_path, (remote_info['mtime'], remote_info['mtime']))
            except Exception as e:
                self.log(f"Error copying {rel_path} to local: {str(e)}")
                
            # Periodic stop check during file transfers
            if stop_check and stop_check() and self.current_file % 5 == 0:
                self.log("Remote to local sync stopped during transfer")
                return False
        
        return True

# Keep the original functions for backward compatibility
def get_file_hash(file_path):
    syncer = FolderSync()
    return syncer.get_file_hash(file_path)

def get_remote_file_hash(sftp, file_path):
    syncer = FolderSync()
    return syncer.get_remote_file_hash(sftp, file_path)

def list_local_files(local_dir):
    syncer = FolderSync()
    return syncer.list_local_files(local_dir)

def list_remote_files(sftp, remote_dir):
    syncer = FolderSync()
    return syncer.list_remote_files(sftp, remote_dir)

def sync_directories(ssh_host, ssh_port, ssh_user, ssh_password, local_dir, remote_dir):
    syncer = FolderSync()
    return syncer.sync_directories(ssh_host, ssh_port, ssh_user, ssh_password, local_dir, remote_dir)

def main():
    """Command-line interface for folder synchronization"""
    parser = argparse.ArgumentParser(description="Synchronize folders between local and remote SSH server")
    parser.add_argument("--host", required=True, help="SSH host")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--local-dir", required=True, help="Local directory path")
    parser.add_argument("--remote-dir", required=True, help="Remote directory path")
    parser.add_argument("--direction", choices=["both", "to_remote", "to_local"], default="both",
                        help="Sync direction: both ways, local to remote only, or remote to local only")
    parser.add_argument("--extensions", help="Comma-separated list of file extensions to include/exclude (e.g., .txt,.pdf)")
    parser.add_argument("--filter-mode", choices=["include", "exclude"], default="include",
                        help="Whether to include only or exclude the specified extensions")
    
    args = parser.parse_args()
    
    # Process extensions
    extension_filters = None
    if args.extensions:
        extension_filters = []
        for ext in args.extensions.split(','):
            ext = ext.strip()
            if not ext.startswith('.'):
                ext = '.' + ext
            extension_filters.append('*' + ext)
    
    syncer = FolderSync()
    syncer.sync_directories(
        args.host, args.port, args.username, args.password, 
        args.local_dir, args.remote_dir, 
        bidirectional=(args.direction == "both"),
        sync_mode=args.direction,
        extension_filters=extension_filters,
        filter_mode=args.filter_mode
    )

if __name__ == "__main__":
    main() 