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
from io import BytesIO
import tempfile
import zipfile
import io
import mimetypes
import shutil

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
    
    def update_progress(self, status_message=None, progress=None):
        """Update progress and optionally status message using the callback if available"""
        if self.callback:
            self.callback(status_message=status_message, progress=progress)
        else:
            if status_message:
                print(f"{status_message} - {progress}%")
    
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
    
    def get_remote_file_hash(self, sftp, file_path, timeout=30, max_size=100*1024*1024):
        """Calculate MD5 hash for a remote file with timeout and max size limits
        
        Args:
            sftp: SFTP client
            file_path: Path to the remote file
            timeout: Maximum time in seconds to spend calculating hash (0 for no timeout)
            max_size: Maximum file size in bytes to fully hash (0 for no limit)
        """
        hash_md5 = hashlib.md5()
        
        try:
            # Get file size
            stat = sftp.stat(file_path)
            file_size = stat.st_size
            file_size_mb = file_size / (1024 * 1024)
            
            # For very large files, use a partial hash approach if max_size is set
            if max_size > 0 and file_size > max_size:
                self.log(f"Using partial hash for large file {file_path} ({file_size_mb:.2f} MB)")
                try:
                    with sftp.open(file_path, "rb") as f:
                        # Read first 50KB
                        start_data = f.read(50*1024)
                        hash_md5.update(start_data)
                        
                        # Only try to read the end if file is large enough
                        if file_size > 100*1024:
                            try:
                                # Skip to the end and read last 50KB
                                f.seek(max(0, file_size - 50*1024))
                                end_data = f.read(50*1024)
                                hash_md5.update(end_data)
                            except Exception as e:
                                # If seeking fails, just use what we have plus the size
                                self.log(f"Error seeking to end of file {file_path}: {str(e)}")
                        
                    # Add size as part of the hash to differentiate similar files
                    hash_md5.update(str(file_size).encode())
                    return hash_md5.hexdigest()
                except Exception as e:
                    self.log(f"Error calculating partial hash for {file_path}: {str(e)}")
                    # Return a special marker with file size to still have some data
                    return f"partial_error_{file_size}"
            
            # For normal-sized files, or if max_size is disabled
            start_time = time.time()
            bytes_read = 0
            
            try:
                with sftp.open(file_path, "rb") as f:
                    # Use smaller chunks for more frequent timeout checks
                    chunk_size = 64*1024  # 64KB chunks
                    
                    while True:
                        # Check timeout before reading the next chunk
                        if timeout > 0 and (time.time() - start_time > timeout):
                            elapsed = time.time() - start_time
                            self.log(f"Timeout calculating hash for {file_path} after {elapsed:.1f} seconds ({bytes_read/1024/1024:.2f}MB read)")
                            
                            # Return a special marker for timeout with how much we processed
                            if bytes_read > 0:
                                # Add size to the hash to still have some differential
                                hash_md5.update(str(file_size).encode())
                                return f"timeout_partial_{hash_md5.hexdigest()}"
                            else:
                                return f"timeout_zero_{file_size}"
                        
                        # Read a chunk with a short timeout
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break  # End of file
                        
                        hash_md5.update(chunk)
                        bytes_read += len(chunk)
                        
                        # Log progress for very large files
                        if bytes_read > 10*1024*1024 and bytes_read % (5*1024*1024) < chunk_size:
                            mb_read = bytes_read / 1024 / 1024
                            elapsed = time.time() - start_time
                            rate = mb_read / elapsed if elapsed > 0 else 0
                            self.log(f"Still hashing {file_path}: {mb_read:.1f}MB read at {rate:.1f}MB/s")
                
                # If we get here, we successfully read the whole file
                elapsed = time.time() - start_time
                if elapsed > 5:  # Only log timing for files that took more than 5 seconds
                    self.log(f"Completed hash for {file_path} in {elapsed:.1f} seconds ({file_size_mb:.2f}MB)")
                
                return hash_md5.hexdigest()
                
            except Exception as e:
                elapsed = time.time() - start_time
                self.log(f"Error after {elapsed:.1f}s calculating hash for {file_path}: {str(e)}")
                
                # If we read some data, return a partial hash
                if bytes_read > 0:
                    hash_md5.update(str(file_size).encode())
                    return f"error_partial_{hash_md5.hexdigest()}"
                else:
                    return f"error_zero_{file_size}"
                
        except Exception as e:
            self.log(f"Error accessing remote file {file_path}: {str(e)}")
            return None
    
    def calculate_hash_batch(self, files_to_hash, is_remote=False, sftp=None, timeout=30, max_size=100*1024*1024):
        """Calculate hashes for a batch of files and return the results"""
        results = {}
        for rel_path, info in files_to_hash.items():
            if is_remote:
                hash_value = self.get_remote_file_hash(sftp, info['path'], timeout=timeout, max_size=max_size)
            else:
                hash_value = self.get_file_hash(info['path'])
                
            results[rel_path] = hash_value
            
        return results
    
    def calculate_hashes_parallel(self, files_dict, is_remote=False, sftp=None, stop_check=None):
        """Calculate hashes for multiple files in parallel using multiple cores"""
        if not files_dict:
            return {}
            
        # Check if we should stop
        if stop_check and stop_check():
            self.log("Hash calculation stopped by user")
            return {}
            
        # Identify files that need hashes calculated
        files_to_hash = {rel_path: info for rel_path, info in files_dict.items() 
                         if info['hash'] is None}
        
        if not files_to_hash:
            return {}
            
        total_files = len(files_to_hash)
        self.log(f"Calculating hashes for {total_files} files using {self.max_workers} workers")
        
        # For remote files, use a more cautious sequential approach
        if is_remote:
            return self._calculate_remote_hashes_sequentially(files_to_hash, sftp, stop_check)
        
        # For local files, continue with parallel processing
        # Divide work into smaller batches for more frequent progress updates and cancellation checks
        batch_size = max(1, min(10, total_files // (self.max_workers * 2)))
        batches = []
        current_batch = {}
        count = 0
        
        for rel_path, info in files_to_hash.items():
            # Check more frequently if we should stop
            if count % 20 == 0 and stop_check and stop_check():
                self.log("Hash calculation stopped by user during batch creation")
                return {}
                
            current_batch[rel_path] = info
            count += 1
            
            if count >= batch_size:
                batches.append(current_batch)
                current_batch = {}
                count = 0
                
        if current_batch:
            batches.append(current_batch)
        
        results = {}
        completed_batches = 0
        completed_files = 0
        total_batches = len(batches)
        failed_files = 0
        timeout_files = 0
        
        # Process batches in parallel using ThreadPoolExecutor for local files
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit all batches to the executor
            for batch in batches:
                future = executor.submit(self.calculate_hash_batch, batch, False, None)
                futures.append((future, len(batch)))
            
            # Process results as they complete
            for future, batch_size in futures:
                # Check if we should stop
                if stop_check and stop_check():
                    self.log("Hash calculation stopped by user")
                    executor.shutdown(wait=False)  # Force shutdown the executor
                    return results
                
                try:
                    # Wait for this batch with a timeout
                    try:
                        batch_results = future.result(timeout=300)  # 5-minute timeout per batch
                    except TimeoutError:
                        self.log(f"Batch processing timed out after 300 seconds")
                        failed_files += batch_size
                        completed_batches += 1
                        continue
                    
                    # Count timeouts in results
                    for hash_value in batch_results.values():
                        if hash_value and hash_value.startswith("timeout_partial_"):
                            timeout_files += 1
                    
                    # Update our combined results
                    results.update(batch_results)
                    
                    # Update progress
                    completed_batches += 1
                    completed_files += len(batch_results)
                    
                    if self.callback:
                        progress = (completed_files / total_files) * 100
                        self.callback(
                            status_message=f"Calculating hashes: {completed_files}/{total_files} files, {timeout_files} timeouts",
                            progress=progress
                        )
                        
                except Exception as e:
                    self.log(f"Error in hash calculation batch: {str(e)}")
                    failed_files += batch_size
                    completed_batches += 1
        
        # Report final status
        if timeout_files > 0 or failed_files > 0:
            self.log(f"Hash calculation completed with {timeout_files} timeouts and {failed_files} failures")
        
        # Update the original dictionary with the calculated hashes
        for rel_path, hash_value in results.items():
            files_dict[rel_path]['hash'] = hash_value
            
        return results
    
    def _calculate_remote_hashes_sequentially(self, files_to_hash, sftp, stop_check=None):
        """Calculate hashes for remote files one by one with strict timeouts
        
        This more cautious approach prevents the entire process from getting stuck
        if there are issues with specific files.
        """
        results = {}
        total_files = len(files_to_hash)
        processed = 0
        skipped = 0
        timeout_per_file = 60  # 1 minute max per file
        
        # Sort files by size (smallest first) to get some quick wins
        sorted_files = sorted(files_to_hash.items(), key=lambda x: x[1]['size'])
        
        self.log(f"Processing {total_files} remote files sequentially with {timeout_per_file}s timeout per file")
        
        for rel_path, info in sorted_files:
            # Check if we should stop
            if stop_check and stop_check():
                self.log(f"Remote hash calculation stopped by user after processing {processed}/{total_files} files")
                break
                
            processed += 1
            file_size_mb = info['size'] / (1024 * 1024)
            self.log(f"Processing file {processed}/{total_files}: {rel_path} ({file_size_mb:.2f} MB)")
            
            # Update progress frequently
            if self.callback:
                progress = (processed / total_files) * 100
                self.callback(
                    status_message=f"Calculating hash: {processed}/{total_files} ({skipped} skipped)",
                    progress=progress
                )
            
            # Skip very large files automatically (over 100MB)
            if info['size'] > 100 * 1024 * 1024:
                self.log(f"Skipping large file {rel_path} ({file_size_mb:.2f} MB) - using partial hash")
                # Use partial hash (first/last 50KB + size)
                try:
                    hash_value = self.get_remote_file_hash(sftp, info['path'], timeout=timeout_per_file, 
                                                         max_size=1)  # Force partial hash
                    results[rel_path] = hash_value
                    continue
                except Exception as e:
                    self.log(f"Error calculating partial hash for {rel_path}: {str(e)}")
                    results[rel_path] = f"error_hash_{info['size']}"
                    skipped += 1
                    continue
            
            # For normal files, try with timeout
            try:
                hash_value = self.get_remote_file_hash(sftp, info['path'], timeout=timeout_per_file)
                
                # Check if it was a timeout
                if hash_value and hash_value.startswith("timeout_partial_"):
                    skipped += 1
                    self.log(f"File {rel_path} hash calculation timed out after {timeout_per_file}s")
                
                results[rel_path] = hash_value
                
            except Exception as e:
                self.log(f"Error calculating hash for {rel_path}: {str(e)}")
                results[rel_path] = f"error_hash_{info['size']}"
                skipped += 1
        
        self.log(f"Completed remote hash calculation: {processed} processed, {skipped} skipped/timeout")
        
        # Update the original dictionary with the calculated hashes
        for rel_path, hash_value in results.items():
            if rel_path in files_to_hash:
                files_to_hash[rel_path]['hash'] = hash_value
        
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
    
    def list_local_files(self, local_dir, ignore_patterns=None, extension_filters=None, filter_mode="include", folder_exclusions=None, calculate_hashes=False, stop_check=None, use_cache_only=False):
        """List all files in the local directory with their MD5 hashes
        
        If use_cache_only is True, only files in the cache will be checked (faster but may miss new files)
        """
        if ignore_patterns is None:
            ignore_patterns = []
            
        if folder_exclusions is None:
            folder_exclusions = []
            
        result = {}
        
        # Try to load from cache first
        cached_metadata = self.load_local_metadata()
        
        if use_cache_only and cached_metadata:
            self.log("Using cached metadata only for local files (faster, but new files won't be detected)")
        
        try:
            if not os.path.exists(local_dir):
                self.log(f"Local directory {local_dir} does not exist")
                return {}
            
            # First, check which files still exist and have the same metadata
            cached_files_still_valid = set()
            
            for rel_path, cached_info in cached_metadata.items():
                # Check if we should stop
                if stop_check and stop_check():
                    self.log("Local file scanning stopped by user request")
                    return {}
                    
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
            
            # If use_cache_only is True and no files match the filter, fall back to full scan
            if use_cache_only and not result:
                self.log("WARNING: No files in the local cache match the current filter settings")
                self.log("Falling back to full directory scan to ensure files are found")
                use_cache_only = False
            
            # If use_cache_only is True, skip the full directory scan
            if not use_cache_only:
                # Now scan for new files
                for root, dirs, files in os.walk(local_dir):
                    # Check if we should stop
                    if stop_check and stop_check():
                        self.log("Local file scanning stopped by user request during directory walk")
                        break
                        
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
            
            if use_cache_only:
                self.log(f"Found {len(result)} valid files in local cache")
            else:
                self.log(f"Found {len(result)} files in local directory (of which {len(cached_files_still_valid)} from cache)")
            
            # Calculate hashes in parallel if requested
            if calculate_hashes:
                self.log("Pre-calculating hashes for local files...")
                self.calculate_hashes_parallel(result, is_remote=False, stop_check=stop_check)
            
            # Store the local metadata for later saving
            self.local_metadata = result
            
            return result
            
        except Exception as e:
            self.log(f"Error scanning local directory: {str(e)}")
            return {}
    
    def list_remote_files(self, sftp, remote_dir, ignore_patterns=None, extension_filters=None, filter_mode="include", folder_exclusions=None, calculate_hashes=False, stop_check=None, use_cache_only=False):
        """List all files in the remote directory with their MD5 hashes
        
        If use_cache_only is True, only files in the cache will be checked (faster but may miss new files)
        """
        import stat  # Ensure stat is accessible in this scope for the nested function
        
        if ignore_patterns is None:
            ignore_patterns = []
            
        if folder_exclusions is None:
            folder_exclusions = []
            
        result = {}
        
        # Try to load from cache first
        cached_metadata = self.load_remote_metadata()
        
        if use_cache_only and cached_metadata:
            self.log("Using cached metadata only for remote files (faster, but new files won't be detected)")
        
        # Add debug logging for initial parameters
        self.log(f"DEBUG: Starting remote file scan with path: '{remote_dir}'")
        self.log(f"DEBUG: Extension filters: {extension_filters}, mode: {filter_mode}")
        self.log(f"DEBUG: Folder exclusions: {folder_exclusions}")
        self.log(f"DEBUG: use_cache_only: {use_cache_only}, cached_metadata entries: {len(cached_metadata)}")
        
        try:
            files_found = set()
            
            # When use_cache_only is True, only check files in the cache
            if use_cache_only:
                for rel_path, cached_info in cached_metadata.items():
                    # Check if we should stop
                    if stop_check and stop_check():
                        self.log("Remote file checking stopped by user request")
                        return {}
                    
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
                        file_name = os.path.basename(rel_path)
                        file_matches_filter = False
                        for pattern in extension_filters:
                            if fnmatch.fnmatch(file_name, pattern):
                                file_matches_filter = True
                                break
                        
                        # Skip based on filter mode
                        if (filter_mode == "include" and not file_matches_filter) or \
                           (filter_mode == "exclude" and file_matches_filter):
                            continue
                    
                    # Try to check if the file still exists and has the same attributes
                    full_path = (remote_dir + rel_path).replace('//', '/')
                    try:
                        stat = sftp.stat(full_path)
                        # If file exists, check if it has changed
                        current_size = stat.st_size
                        current_mtime = stat.st_mtime
                        
                        # If size and mtime match exactly, keep the cached info
                        if abs(cached_info['size'] - current_size) < 2 and abs(cached_info['mtime'] - current_mtime) < 2:
                            result[rel_path] = cached_info.copy()
                        else:
                            # File changed, update info
                            result[rel_path] = {
                                'path': full_path,
                                'hash': None,  # Hash is invalidated
                                'size': current_size,
                                'mtime': current_mtime
                            }
                        
                        # Update progress periodically
                        if len(result) % 50 == 0 and self.callback:
                            self.callback(
                                status_message=f"Checked {len(result)} remote files from cache so far...",
                                progress=None
                            )
                    except FileNotFoundError:
                        # File no longer exists, skip it
                        self.log(f"DEBUG: Cached file not found: {full_path}")
                        continue
                    except Exception as e:
                        self.log(f"Error checking remote file {full_path}: {str(e)}")
                        # Skip this file on error
                        continue
                
                # If no files matched the filter, fall back to full directory scan
                if not result:
                    self.log("WARNING: No files in the remote cache match the current filter settings")
                    self.log("Falling back to full directory scan to ensure files are found")
                    use_cache_only = False
                else:
                    self.log(f"Found {len(result)} valid files in remote cache")
            
            # When use_cache_only is False, perform a full directory scan
            if not use_cache_only:
                def scan_remote_dir(sftp, path, base_path, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes, stop_check):
                    # Check if we should stop
                    if stop_check and stop_check():
                        return True  # Signal to stop scanning
                        
                    try:
                        self.log(f"DEBUG: Scanning remote directory: '{path}'")
                        entries = sftp.listdir_attr(path)
                        self.log(f"DEBUG: Found {len(entries)} entries in directory '{path}'")
                    except Exception as e:
                        self.log(f"ERROR scanning remote directory {path}: {str(e)}")
                        return False  # Continue with other directories
                        
                    # Update progress every directory
                    if self.callback:
                        self.callback(status_message=f"Scanning remote directory: {path}")
                        
                    for entry in entries:
                        # Check if we should stop more frequently
                        if stop_check and stop_check() and len(result) % 20 == 0:
                            return True  # Signal to stop scanning
                            
                        # Get full path
                        name = entry.filename
                        full_path = os.path.join(path, name).replace('\\', '/')
                        
                        # Skip hidden files and directories
                        if name.startswith('.'):
                            self.log(f"DEBUG: Skipping hidden entry: {name}")
                            continue
                            
                        # Get relative path
                        rel_path = os.path.relpath(full_path, base_path).replace('\\', '/')
                        
                        # If it's a directory, recurse
                        if stat.S_ISDIR(entry.st_mode):
                            # Check if directory should be excluded
                            should_exclude = False
                            for exclusion in folder_exclusions:
                                if rel_path == exclusion or rel_path.startswith(exclusion + '/'):
                                    should_exclude = True
                                    self.log(f"DEBUG: Excluding directory: {rel_path} (matches exclusion: {exclusion})")
                                    break
                                    
                            if should_exclude:
                                continue
                                
                            # Recurse into subdirectory
                            if scan_remote_dir(sftp, full_path, base_path, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes, stop_check):
                                return True  # Propagate stop signal up
                        
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
                                    self.log(f"DEBUG: Skipping file due to filter: {name} (filter_mode: {filter_mode}, matches_filter: {file_matches_filter})")
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
                            
                            # Update progress periodically during scanning
                            if len(result) % 50 == 0 and self.callback:
                                self.callback(
                                    status_message=f"Found {len(result)} remote files so far...",
                                    progress=None
                                )
                    
                    return False  # Continue scanning
                
                # Ensure remote_dir ends with '/'
                if not remote_dir.endswith('/'):
                    remote_dir += '/'
                    self.log(f"DEBUG: Adjusted remote directory path to ensure it ends with '/': {remote_dir}")
                    
                # Start recursive scan
                self.log(f"DEBUG: Starting recursive scan of remote directory: {remote_dir}")
                try:
                    # Test if the remote directory exists before starting scan
                    sftp.stat(remote_dir)
                    self.log(f"DEBUG: Remote directory exists: {remote_dir}")
                except Exception as e:
                    self.log(f"ERROR: Remote directory doesn't exist or not accessible: {remote_dir} - {str(e)}")
                    return {}
                
                stopped = scan_remote_dir(sftp, remote_dir, remote_dir, result, files_found, ignore_patterns, extension_filters, filter_mode, folder_exclusions, calculate_hashes, stop_check)
                
                # If stopped, return what we have so far
                if stopped:
                    return result
                    
                cached_files_used = len(set(result.keys()) & set(cached_metadata.keys()))
                new_files_found = len(result) - cached_files_used
                
                self.log(f"Found {len(result)} files in remote directory (of which {cached_files_used} from cache, {new_files_found} new)")
            
            # Calculate hashes in parallel if requested
            if calculate_hashes:
                self.log("Pre-calculating hashes for remote files...")
                self.calculate_hashes_parallel(result, is_remote=True, sftp=sftp, stop_check=stop_check)
            
            # Store the remote metadata for later saving
            self.remote_metadata = result
            
            return result
        
        except Exception as e:
            self.log(f"ERROR in list_remote_files: {str(e)}")
            import traceback
            self.log(f"ERROR Traceback: {traceback.format_exc()}")
            return {}
    
    def sync_with_existing_connection(self, ssh_client, sftp_client, local_dir, remote_dir, 
                                    bidirectional=True, sync_mode="both", 
                                    extension_filters=None, filter_mode="include",
                                    stop_check=None, folder_exclusions=None, content_only_compare=False,
                                    transfer_method="sftp", verbose_logging=True, force_sync=False, use_cache_only=False):
        """Sync files using existing SSH and SFTP connections
        
        If use_cache_only is True, only files in the cache will be checked (faster but may miss new files)
        """
        self.update_status("Starting synchronization with existing connection...")
        
        # Starting timestamp for the operation
        start_time = time.time()
        
        # Local and remote directory should exist
        if not os.path.isdir(local_dir):
            self.log(f"Local directory does not exist: {local_dir}")
            return False
            
        # Ensure local directory path ends with a slash for consistent path manipulation
        if not local_dir.endswith(os.path.sep):
            local_dir = local_dir + os.path.sep
            
        # Ensure remote directory path ends with a slash for consistent path manipulation
        if not remote_dir.endswith('/'):
            remote_dir = remote_dir + '/'
            
        # Try to ensure remote directory exists
        try:
            sftp_client.stat(remote_dir)
        except FileNotFoundError:
            try:
                self.log(f"Remote directory does not exist, creating: {remote_dir}")
                sftp_client.mkdir(remote_dir)
            except Exception as e:
                self.log(f"Failed to create remote directory: {str(e)}")
                return False
                
        # Check if stop was requested after directory creation
        if stop_check and stop_check():
            self.log("Synchronization stopped before file listing")
            return False
            
        # Log sync parameters
        self.log(f"Local directory: {local_dir}")
        self.log(f"Remote directory: {remote_dir}")
        self.log(f"Sync mode: {sync_mode}")
        self.log(f"Transfer method: {transfer_method}")
        if extension_filters:
            if filter_mode == "include":
                self.log(f"Including extensions: {extension_filters}")
            else:
                self.log(f"Excluding extensions: {extension_filters}")
                
        if content_only_compare:
            self.log("Using content-only comparison (slower but more accurate)")
        else:
            self.log("Using quick comparison (size and modification time)")
            
        # Log excluded folders if any
        if folder_exclusions:
            self.log(f"Excluded folders: {', '.join(folder_exclusions)}")
        
        # Log force sync status
        if force_sync:
            self.log("FORCE SYNC ENABLED: All files will be transferred regardless of comparison")
            
        # Log cache usage
        if use_cache_only:
            self.log("USING CACHE ONLY: Only checking files in the cache (faster, but new files won't be detected)")
        
        # Create .synccache directory if it doesn't exist
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".synccache")
        try:
            os.makedirs(cache_dir, exist_ok=True)
            self.log(f"Cache directory verified/created at: {cache_dir}")
        except Exception as e:
            self.log(f"Warning: Could not create cache directory: {str(e)}")
        
        # Scan directories
        self.update_status("Scanning local directory...")
        local_files = self.list_local_files(
            local_dir, 
            extension_filters=extension_filters, 
            filter_mode=filter_mode,
            folder_exclusions=folder_exclusions,
            calculate_hashes=content_only_compare,
            stop_check=stop_check,
            use_cache_only=use_cache_only
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
            calculate_hashes=content_only_compare,
            stop_check=stop_check,
            use_cache_only=use_cache_only
        )
        
        # Log files that exist on remote but not on local
        remote_only_files = [path for path in remote_files if path not in local_files]
        if remote_only_files:
            self.log(f"Found {len(remote_only_files)} files on remote that don't exist locally:")
            for i, path in enumerate(remote_only_files[:10]):  # Show just first 10 to avoid log spam
                self.log(f"  {i+1}. {path}")
            if len(remote_only_files) > 10:
                self.log(f"  ... plus {len(remote_only_files) - 10} more")
        else:
            self.log("No remote-only files found.")
            
        # Check if stop was requested
        if stop_check and stop_check():
            self.log("Synchronization stopped after scanning directories")
            return False
        
        # Perform sync based on direction
        sync_success = True
        
        # Local to remote sync if needed
        if sync_mode in ["both", "to_remote"]:
            to_remote_success = self._sync_local_to_remote(
                ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, 
                stop_check, content_only_compare, transfer_method, verbose_logging, force_sync
            )
            sync_success = sync_success and to_remote_success
            
        # Remote to local sync if needed
        if sync_mode in ["both", "to_local"]:
            to_local_success = self._sync_remote_to_local(
                ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, 
                stop_check, content_only_compare, transfer_method, verbose_logging, force_sync
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
        
        return True
    
    def sync_directories(self, host, port, username, password, local_dir, remote_dir, 
                       bidirectional=True, sync_mode="both", 
                       extension_filters=None, filter_mode="include",
                       stop_check=None, folder_exclusions=None, content_only_compare=False,
                       transfer_method="sftp", verbose_logging=True, force_sync=False, use_cache_only=False):
        """
        Sync local and remote directories using SSH, SFTP or SCP
        
        host: SSH host
        port: SSH port
        username: SSH username
        password: SSH password
        local_dir: Local directory path
        remote_dir: Remote directory path
        bidirectional: Whether to sync in both directions
        sync_mode: "both", "to_remote", or "to_local"
        extension_filters: List of file extensions to include/exclude
        filter_mode: "include" or "exclude"
        stop_check: Callable that returns True if sync should be stopped
        folder_exclusions: List of folder names to exclude
        content_only_compare: Whether to compare by content hash only
        transfer_method: "sftp" or "scp" for file transfers
        verbose_logging: Whether to log detailed file differences
        force_sync: When True, transfer all files regardless of comparison
        use_cache_only: When True, only check files in the cache (faster but may miss new files)
        """
        # Create SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.load_system_host_keys()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to SSH server
            self.update_status("Connecting to SSH server...")
            ssh_client.connect(host, port=port, username=username, password=password)
            
            # Create SFTP client (needed for listing files even with SCP)
            sftp_client = ssh_client.open_sftp()
            
            # Call sync with existing connection
            return self.sync_with_existing_connection(
                ssh_client, sftp_client, local_dir, remote_dir, 
                bidirectional, sync_mode, extension_filters, filter_mode,
                stop_check, folder_exclusions, content_only_compare, transfer_method, 
                verbose_logging, force_sync, use_cache_only
            )
        
        except Exception as e:
            error_msg = f"Error during synchronization: {str(e)}"
            self.log(error_msg)
            traceback.print_exc()
            return False
        
        finally:
            # Close connections
            try:
                if 'sftp_client' in locals():
                    sftp_client.close()
                if 'ssh_client' in locals():
                    ssh_client.close()
            except:
                pass
    
    def _sync_local_to_remote(self, ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, stop_check=None, content_only_compare=False, transfer_method="sftp", verbose_logging=False, force_sync=False):
        """Sync files from local to remote"""
        self.update_status("Syncing local to remote...")
        synced_files = 0
        errors = 0
        
        # Ensure paths end with separator
        if not local_dir.endswith(os.path.sep):
            local_dir = local_dir + os.path.sep
            
        if not remote_dir.endswith('/'):
            remote_dir = remote_dir + '/'
        
        # Calculate total files to sync (for progress indication)
        total_to_sync = sum(1 for local_path in local_files if local_path not in remote_files or 
                          self._files_differ(local_files[local_path], remote_files.get(local_path), content_only_compare))
        
        if total_to_sync == 0:
            self.log("No files need to be synced from local to remote")
            return synced_files, errors
        
        self.log(f"Found {total_to_sync} files to sync from local to remote")
        files_processed = 0
        
        # Go through each local file
        for rel_path, local_info in local_files.items():
            if stop_check and stop_check():
                self.log("Sync stopped by user")
                break
                
            # Check if file exists remotely and if it has changed
            need_sync = rel_path not in remote_files or self._files_differ(local_info, remote_files.get(rel_path), content_only_compare)
            
            if need_sync:
                local_path = local_info['path']
                remote_path = remote_dir + rel_path.replace('\\', '/')
                
                # Ensure the remote directory exists
                remote_dir_path = os.path.dirname(remote_path)
                try:
                    try:
                        sftp_client.stat(remote_dir_path)
                    except FileNotFoundError:
                        # Create directory and all parent directories
                        self._create_remote_dirs(sftp_client, remote_dir_path)
                    
                    # Transfer the file based on selected method
                    if transfer_method == "scp":
                        # Use SCP for file transfer
                        self.log(f"Copying (SCP): {local_path} -> {remote_path}")
                        
                        # Since paramiko doesn't have a direct SCP implementation,
                        # we'll execute the scp command via SSH
                        # First create a temporary file with the source path
                        temp_file_path = f"/tmp/scp_source_path_{os.path.basename(local_path)}"
                        with open(local_path, 'rb') as f:
                            file_content = f.read()
                        
                        # Use SFTP to transfer the file to a temporary location first
                        # (this is more reliable than trying to transfer binary data via command)
                        temp_remote_path = f"/tmp/scp_temp_{os.path.basename(local_path)}"
                        sftp_client.putfo(BytesIO(file_content), temp_remote_path)
                        
                        # Now move it to the destination using the mv command
                        cmd = f"mkdir -p '{os.path.dirname(remote_path)}' && mv '{temp_remote_path}' '{remote_path}'"
                        stdin, stdout, stderr = ssh_client.exec_command(cmd)
                        exit_status = stdout.channel.recv_exit_status()
                        
                        if exit_status != 0:
                            error_output = stderr.read().decode('utf-8')
                            self.log(f"SCP transfer failed for {local_path}: {error_output}")
                            errors += 1
                        else:
                            synced_files += 1
                            # Log detailed information about synced file if verbose logging is enabled
                            if verbose_logging:
                                if rel_path not in remote_files:
                                    self.log(f"File synced: {rel_path} (new file, did not exist on remote)")
                                else:
                                    remote_info = remote_files.get(rel_path)
                                    if content_only_compare:
                                        self.log(f"File synced: {rel_path} (content was different)")
                                    else:
                                        size_diff = abs(local_info['size'] - remote_info['size']) >= 10
                                        time_diff = abs(local_info['mtime'] - remote_info['mtime']) >= 5
                                        
                                        if size_diff and time_diff:
                                            self.log(f"File synced: {rel_path} (size and modification time were different)")
                                        elif size_diff:
                                            self.log(f"File synced: {rel_path} (size was different: local={local_info['size']}, remote={remote_info['size']})")
                                        elif time_diff:
                                            self.log(f"File synced: {rel_path} (modification time was different: local={local_info['mtime']}, remote={remote_info['mtime']})")
                    else:
                        # Use SFTP for file transfer
                        self.log(f"Copying (SFTP): {local_path} -> {remote_path}")
                        try:
                            sftp_client.put(local_path, remote_path)
                            synced_files += 1
                            # Log detailed information about synced file if verbose logging is enabled
                            if verbose_logging:
                                if rel_path not in remote_files:
                                    self.log(f"File synced: {rel_path} (new file, did not exist on remote)")
                                else:
                                    remote_info = remote_files.get(rel_path)
                                    if content_only_compare:
                                        self.log(f"File synced: {rel_path} (content was different)")
                                    else:
                                        size_diff = abs(local_info['size'] - remote_info['size']) >= 10
                                        time_diff = abs(local_info['mtime'] - remote_info['mtime']) >= 5
                                        
                                        if size_diff and time_diff:
                                            self.log(f"File synced: {rel_path} (size and modification time were different)")
                                        elif size_diff:
                                            self.log(f"File synced: {rel_path} (size was different: local={local_info['size']}, remote={remote_info['size']})")
                                        elif time_diff:
                                            self.log(f"File synced: {rel_path} (modification time was different: local={local_info['mtime']}, remote={remote_info['mtime']})")
                        except Exception as e:
                            self.log(f"SFTP transfer failed for {local_path}: {str(e)}")
                            errors += 1
                
                except Exception as e:
                    self.log(f"Error syncing {local_path}: {str(e)}")
                    errors += 1
                
                files_processed += 1
                progress = (files_processed / total_to_sync) * 100
                self.update_progress(f"Transferring file {files_processed}/{total_to_sync}", progress)
                
        self.log(f"Local to remote sync complete: {synced_files} files synced, {errors} errors")
        return synced_files, errors
    
    def _sync_remote_to_local(self, ssh_client, sftp_client, local_dir, remote_dir, local_files, remote_files, stop_check=None, content_only_compare=False, transfer_method="sftp", verbose_logging=False, force_sync=False):
        """Sync files from remote to local"""
        self.update_status("Syncing remote to local...")
        synced_files = 0
        errors = 0
        
        # Check if we should stop before starting
        if stop_check and stop_check():
            self.log("Sync stopped by user before starting remote to local sync")
            return synced_files, errors
        
        # Ensure paths end with separator
        if not local_dir.endswith(os.path.sep):
            local_dir = local_dir + os.path.sep
            
        if not remote_dir.endswith('/'):
            remote_dir = remote_dir + '/'
        
        # Check if we should stop before calculating total files
        if stop_check and stop_check():
            self.log("Sync stopped by user before counting files to sync")
            return synced_files, errors
            
        # Calculate total files to sync
        if force_sync:
            # If force sync is enabled, sync all remote files
            self.log("Force sync enabled - will transfer all remote files")
            total_to_sync = len(remote_files)
        else:
            # Check files that differ, but with periodic stop checks
            files_to_sync = []
            count = 0
            
            for remote_path in remote_files:
                # Check periodically for stop requests during computation
                count += 1
                if count % 50 == 0 and stop_check and stop_check():
                    self.log("Sync stopped by user during file difference calculation")
                    return synced_files, errors
                    
                if remote_path not in local_files or self._files_differ(remote_files[remote_path], local_files.get(remote_path), content_only_compare):
                    files_to_sync.append(remote_path)
                    
            total_to_sync = len(files_to_sync)
        
        # Check again if we should stop after calculating total files
        if stop_check and stop_check():
            self.log("Sync stopped by user after calculating files to sync")
            return synced_files, errors
            
        if total_to_sync == 0:
            self.log("No files need to be synced from remote to local")
            return synced_files, errors
        
        self.log(f"Found {total_to_sync} files to sync from remote to local")
        files_processed = 0
        
        # Go through each remote file
        for rel_path, remote_info in remote_files.items():
            if stop_check and stop_check():
                self.log("Sync stopped by user")
                break
                
            # Check if file should be synced
            need_sync = force_sync or rel_path not in local_files or self._files_differ(remote_info, local_files.get(rel_path), content_only_compare)
            
            if need_sync:
                remote_path = remote_info['path']
                local_path = os.path.join(local_dir, rel_path)
                
                # Ensure the local directory exists
                local_dir_path = os.path.dirname(local_path)
                try:
                    os.makedirs(local_dir_path, exist_ok=True)
                    
                    # Use SFTP for file transfer (SCP not needed for download)
                    self.log(f"Copying: {remote_path} -> {local_path}")
                    
                    try:
                        sftp_client.get(remote_path, local_path)
                        synced_files += 1
                        
                        # Log detailed information about synced file if verbose logging is enabled
                        if verbose_logging:
                            if force_sync and rel_path in local_files:
                                self.log(f"File synced: {rel_path} (force sync mode)")
                            elif rel_path not in local_files:
                                self.log(f"File synced: {rel_path} (new file, did not exist locally)")
                            else:
                                local_info = local_files.get(rel_path)
                                if content_only_compare:
                                    self.log(f"File synced: {rel_path} (content was different)")
                                else:
                                    size_diff = abs(remote_info['size'] - local_info['size']) >= 1
                                    time_diff = abs(remote_info['mtime'] - local_info['mtime']) >= 1
                                    
                                    if size_diff and time_diff:
                                        self.log(f"File synced: {rel_path} (size and modification time were different)")
                                    elif size_diff:
                                        self.log(f"File synced: {rel_path} (size was different: remote={remote_info['size']}, local={local_info['size']})")
                                    elif time_diff:
                                        self.log(f"File synced: {rel_path} (modification time was different: remote={remote_info['mtime']}, local={local_info['mtime']})")
                    except Exception as e:
                        self.log(f"SFTP transfer failed for {remote_path}: {str(e)}")
                        errors += 1
                        
                except Exception as e:
                    self.log(f"Error syncing {remote_path}: {str(e)}")
                    errors += 1
                
                files_processed += 1
                progress = (files_processed / total_to_sync) * 100
                self.update_progress(f"Transferring file {files_processed}/{total_to_sync}", progress)
                
        self.log(f"Remote to local sync complete: {synced_files} files synced, {errors} errors")
        return synced_files, errors

    def _files_differ(self, file1_info, file2_info, content_only_compare=False):
        """
        Determine if two files are different based on the comparison method
        
        file1_info: Dictionary containing file metadata
        file2_info: Dictionary containing file metadata
        content_only_compare: Whether to compare by content hash only
        
        Returns True if files are different, False if they are the same
        """
        # If either file doesn't exist, they differ
        if not file1_info or not file2_info:
            return True
            
        # For content-only comparison, only compare hashes
        if content_only_compare:
            # Calculate hashes if they don't exist
            if file1_info.get('hash') is None or file2_info.get('hash') is None:
                return True  # Can't compare without hashes, so assume they differ
                
            # Compare hashes
            return file1_info['hash'] != file2_info['hash']
        else:
            # For .c and .h files, always verify with hash
            file_path = file1_info.get('path', '')
            if file_path.endswith(('.c', '.h')):
                # Calculate hashes if needed
                if file1_info.get('hash') is None:
                    if 'path' in file1_info:
                        file1_info['hash'] = self.get_file_hash(file1_info['path'])
                if file2_info.get('hash') is None:
                    if 'path' in file2_info:
                        if hasattr(self, 'sftp') and self.sftp:
                            file2_info['hash'] = self.get_remote_file_hash(self.sftp, file2_info['path'])
                        else:
                            file2_info['hash'] = self.get_file_hash(file2_info['path'])
                
                # If we have hashes, use them for comparison
                if file1_info.get('hash') is not None and file2_info.get('hash') is not None:
                    # Log for main.c file to debug
                    if "main.c" in file_path:
                        self.log(f"DEBUG: Hash comparison for {file_path}: {file1_info['hash']} vs {file2_info['hash']}")
                        self.log(f"DEBUG: Hashes differ: {file1_info['hash'] != file2_info['hash']}")
                    
                    return file1_info['hash'] != file2_info['hash']
            
            # Quick comparison based on size and time
            size_same = file1_info['size'] == file2_info['size']
            time_same = abs(file1_info['mtime'] - file2_info['mtime']) < 5  # Increased from 1 to 5 seconds
            
            # Log for main.c file to debug
            if "main.c" in file1_info.get('path', ''):
                self.log(f"DEBUG: Quick comparison for {file1_info['path']}")
                self.log(f"DEBUG: Size same: {size_same}, Time same: {time_same}")
                self.log(f"DEBUG: Size: {file1_info['size']} vs {file2_info['size']}")
                self.log(f"DEBUG: Time: {file1_info['mtime']} vs {file2_info['mtime']}")
            
            # If size and time match, files are the same
            return not (size_same and time_same)

    def _create_remote_dirs(self, sftp, path):
        """
        Create remote directory and all parent directories as needed
        
        sftp: SFTP client
        path: Remote directory path to create
        """
        if path == '/' or not path:
            return
            
        try:
            sftp.stat(path)
        except FileNotFoundError:
            # Create parent directory first
            parent = os.path.dirname(path)
            self._create_remote_dirs(sftp, parent)
            
            # Create this directory
            self.log(f"Creating remote directory: {path}")
            sftp.mkdir(path)

    def compare_files(self, local_file, remote_file, mode="quick"):
        """
        Compare local and remote files to see if they are different
        """
        # Get information about both files
        local_info = os.stat(local_file)
        remote_info = self.sftp.stat(remote_file)
        
        # Quick comparison (size and modification time)
        if mode == "quick":
            # Compare file sizes
            if local_info.st_size != remote_info.st_size:
                self.log(f"Size differs: {local_info.st_size} vs {remote_info.st_size}")
                return True
            
            # Compare modification times with a tolerance of 2 seconds
            time_diff = abs(local_info.st_mtime - remote_info.st_mtime)
            if time_diff > 2:
                self.log(f"Time differs: {time_diff} seconds")
                return True
            
            return False
        
        # Content-based comparison using MD5 checksum
        elif mode == "content":
            # Calculate local file MD5
            local_md5 = self.get_md5(local_file)
            
            # Calculate remote file MD5
            remote_md5 = self.get_remote_md5(remote_file)
            
            # Compare hashes
            if local_md5 != remote_md5:
                self.log(f"Content differs: {local_md5} vs {remote_md5}")
                return True
            
            return False
            
        return True  # Default to returning "different" if unknown mode

    def transfer_directory(self, host, port, username, password, source_dir, dest_dir, direction, 
                          folder_exclusions=None, stop_check=None, use_compression=False, 
                          compression_level="balanced", skip_compressed=True):
        """
        Transfer files from source directory to destination directory.
        No synchronization is performed, files are simply copied.
        
        Parameters:
        - host: SSH host to connect to
        - port: SSH port
        - username: SSH username
        - password: SSH password
        - source_dir: Source directory path
        - dest_dir: Destination directory path
        - direction: "upload" for local to remote, "download" for remote to local
        - folder_exclusions: Optional list of folder names to exclude from transfer
        - stop_check: A callable that returns True if the process should stop
        - use_compression: Whether to use compression
        - compression_level: "fast", "balanced", or "maximum"
        - skip_compressed: Whether to skip already compressed files
        
        Returns:
        - (total_files, transferred_files, error_count)
        """
        self.log(f"Starting file transfer from {source_dir} to {dest_dir}")
        if use_compression:
            self.log(f"Using compression (level: {compression_level}, skip compressed: {skip_compressed})")
        
        # Check if we should stop
        if stop_check and stop_check():
            self.log("Transfer stopped due to user request")
            return 0, 0, 0
        
        # Connect to SSH
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(host, port=port, username=username, password=password)
            
            if direction == "upload" or direction == "download":
                self.sftp = self.ssh.open_sftp()
            else:
                raise ValueError(f"Invalid direction: {direction}")
                
        except Exception as e:
            self.log(f"SSH connection failed: {str(e)}")
            return 0, 0, 1
            
        # Initialize counters
        total_files = 0
        transferred_files = 0
        error_count = 0
        
        try:
            # Prepare the exclusion set
            exclusions = set(folder_exclusions or [])
            
            if use_compression:
                # Handle transfers with compression
                if direction == "upload":
                    # Upload with compression
                    return self._transfer_with_compression_upload(
                        source_dir, dest_dir, exclusions, compression_level, 
                        skip_compressed, stop_check
                    )
                else:
                    # Download with compression
                    return self._transfer_with_compression_download(
                        source_dir, dest_dir, exclusions, compression_level, 
                        skip_compressed, stop_check
                    )
            else:
                # Create a list of all files to transfer
                files_to_transfer = []
                errors = []
                
                # Walk through source directory and collect files
                if direction == "upload":
                    # Local source to remote destination
                    for root, dirs, files in os.walk(source_dir):
                        # Skip excluded directories
                        dirs[:] = [d for d in dirs if d not in exclusions]
                        
                        # Add files to the transfer list
                        for file in files:
                            local_path = os.path.join(root, file)
                            relative_path = os.path.relpath(local_path, source_dir)
                            remote_path = os.path.join(dest_dir, relative_path).replace('\\', '/')
                            files_to_transfer.append((local_path, remote_path))
                            total_files += 1
                else:
                    # Remote source to local destination
                    self._walk_remote_dir(source_dir, dest_dir, files_to_transfer, exclusions, total_files)
                    total_files = len(files_to_transfer)
                
                # Transfer files
                for i, (src_path, dst_path) in enumerate(files_to_transfer):
                    # Check if we should stop
                    if stop_check and stop_check():
                        self.log("Transfer stopped due to user request")
                        break
                        
                    try:
                        # Create parent directories if they don't exist
                        if direction == "upload":
                            # Ensure remote directory exists
                            remote_dir = os.path.dirname(dst_path)
                            self._ensure_remote_dir(remote_dir)
                            
                            # Upload file
                            self.log(f"Uploading {src_path} to {dst_path}")
                            self.sftp.put(src_path, dst_path)
                        else:
                            # Ensure local directory exists
                            local_dir = os.path.dirname(dst_path)
                            os.makedirs(local_dir, exist_ok=True)
                            
                            # Download file
                            self.log(f"Downloading {src_path} to {dst_path}")
                            self.sftp.get(src_path, dst_path)
                            
                        transferred_files += 1
                        
                        # Update progress
                        progress = (i + 1) / len(files_to_transfer) * 100
                        self.update_progress(f"Transferring file {i+1}/{total_files}", progress)
                        
                    except Exception as e:
                        self.log(f"Error transferring file {src_path}: {str(e)}")
                        errors.append((src_path, str(e)))
                        error_count += 1
                
        except Exception as e:
            self.log(f"Transfer process error: {str(e)}")
            error_count += 1
            
        finally:
            # Close connections
            if hasattr(self, 'sftp') and self.sftp:
                self.sftp.close()
            if hasattr(self, 'ssh') and self.ssh:
                self.ssh.close()
                
            self.log(f"Transfer complete: {transferred_files} of {total_files} files transferred with {error_count} errors")
            
        return total_files, transferred_files, error_count
    
    def _transfer_with_compression_upload(self, local_dir, remote_dir, exclusions, 
                                       compression_level, skip_compressed, stop_check):
        """Handle uploading with compression from local to remote"""
        self.log(f"Preparing compressed upload from {local_dir} to {remote_dir}")
        
        # Map compression levels to zipfile compression constants
        compression_map = {
            "fast": zipfile.ZIP_DEFLATED,
            "balanced": zipfile.ZIP_DEFLATED,
            "maximum": zipfile.ZIP_DEFLATED
        }
        
        # Map compression levels to compression values (0-9)
        level_map = {
            "fast": 1,
            "balanced": 6,
            "maximum": 9
        }
        
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
            temp_zip_path = temp_file.name
            
        self.log(f"Creating temporary zip file: {temp_zip_path}")
        
        # Initialize counters
        total_files = 0
        transferred_files = 0
        error_count = 0
        
        try:
            # Check if we need to stop before starting
            if stop_check and stop_check():
                self.log("Upload stopped before starting compression")
                return total_files, transferred_files, error_count
                
            # Step 1: Scan the local directory for all files
            files_to_compress = []
            compressed_extensions = {'.zip', '.gz', '.bz2', '.xz', '.7z', '.rar', 
                                    '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.avi'}
            
            for root, dirs, files in os.walk(local_dir):
                # Check if we need to stop
                if stop_check and stop_check():
                    self.log("Upload stopped during directory scan")
                    return total_files, transferred_files, error_count
                    
                # Process files in this directory
                for file in files:
                    local_path = os.path.join(root, file)
                    relative_path = os.path.relpath(local_path, local_dir)
                    
                    # Skip files that are already compressed if needed
                    _, ext = os.path.splitext(file_path.lower())
                    if skip_compressed and ext in compressed_extensions:
                        self.log(f"Skipping already compressed file: {rel_path}")
                        continue
                    
                    files_to_compress.append((local_path, relative_path))
                    
                    total_files += 1
            
            # Check if we have files to compress
            if not files_to_compress:
                self.log("No files to compress and transfer")
                return total_files, 0, 0
                
            # Check if we need to stop before compressing
            if stop_check and stop_check():
                self.log("Upload stopped before compression")
                return total_files, transferred_files, error_count
                
            # Step 2: Create a ZIP file with all the files
            self.log(f"Compressing {len(files_to_compress)} files...")
            
            with zipfile.ZipFile(temp_zip_path, 'w', 
                                compression=compression_map[compression_level],
                                compresslevel=level_map[compression_level]) as zipf:
                
                # Write files to the zip
                for i, (file_path, rel_path) in enumerate(files_to_compress):
                    # Check if we need to stop
                    if i % 10 == 0 and stop_check and stop_check():
                        self.log("Upload stopped during compression")
                        return total_files, transferred_files, error_count
                        
                    try:
                        # Add the file to the zip
                        zipf.write(file_path, rel_path)
                        
                        # Update progress for compression phase (50% of total)
                        progress = (i + 1) / len(files_to_compress) * 50
                        self.update_progress(f"Compressing file {i+1}/{len(files_to_compress)}", progress)
                        
                    except Exception as e:
                        self.log(f"Error compressing {rel_path}: {str(e)}")
            
            # Get the size of the zip file for progress tracking
            zip_size = os.path.getsize(temp_zip_path)
            self.log(f"Compressed archive size: {zip_size} bytes")
            
            # Check if we need to stop before uploading
            if stop_check and stop_check():
                self.log("Upload stopped after compression")
                return total_files, transferred_files, error_count
                
            # Step 3: Create a temporary script to extract the zip on the remote side
            with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as script_file:
                script_path = script_file.name
                
                # Write extraction script
                script_content = f"""#!/usr/bin/env python3
import zipfile
import os
import sys

def extract_zip(zip_path, target_dir):
    print(f"Extracting {{zip_path}} to {{target_dir}}")
    
    # Ensure the target directory exists
    os.makedirs(target_dir, exist_ok=True)
    
    # Extract the zip file
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        # Get total number of items
        total_items = len(zipf.infolist())
        
        # Extract all files
        for i, item in enumerate(zipf.infolist()):
            # Print progress
            if (i + 1) % 10 == 0 or (i + 1) == total_items:
                print(f"Extracting files: {{i+1}}/{{total_items}}")
                
            # Make sure the directory exists
            item_dir = os.path.dirname(os.path.join(target_dir, item.filename))
            if item_dir:
                os.makedirs(item_dir, exist_ok=True)
                
            zipf.extract(item, target_dir)
    
    print("Extraction complete")
    return True

# Run the extraction
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract.py <zip_file> <target_dir>")
        sys.exit(1)
        
    zip_path = sys.argv[1]
    target_dir = sys.argv[2]
    
    success = extract_zip(zip_path, target_dir)
    sys.exit(0 if success else 1)
"""
                script_file.write(script_content.encode('utf-8'))
            
            # Upload the temporary script
            remote_script_path = f"{remote_dir}/_extract_temp.py"
            self.log(f"Uploading extraction script to {remote_script_path}")
            
            try:
                self.sftp.put(script_path, remote_script_path)
                self.sftp.chmod(remote_script_path, 0o755)  # Make executable
            except Exception as e:
                self.log(f"Error uploading extraction script: {str(e)}")
                
            # Check if we need to stop before uploading zip
            if stop_check and stop_check():
                self.log("Upload stopped before uploading zip")
                return total_files, transferred_files, error_count
                
            # Upload the zip file
            remote_zip_path = f"{remote_dir}/_transfer_temp.zip"
            self.log(f"Uploading compressed archive to {remote_zip_path}")
            
            # Upload with progress tracking
            progress_callback = lambda bytes_so_far: self.update_progress(
                f"Uploading archive: {bytes_so_far/zip_size*100:.1f}%", 
                50 + (bytes_so_far / zip_size) * 25
            )
            
            try:
                # For progress tracking, we need to implement our own put function
                # or use a third-party library, since paramiko doesn't have built-in progress
                # callback. For now, we'll just update after the upload.
                self.sftp.put(temp_zip_path, remote_zip_path)
            except Exception as e:
                self.log(f"Error uploading compressed archive: {str(e)}")
                
            # Update progress after upload
            self.update_progress("Archive uploaded, starting extraction", 75)
            
            # Check if we need to stop before extracting
            if stop_check and stop_check():
                self.log("Upload stopped before extraction")
                return total_files, transferred_files, error_count
                
            # Run the extraction script on the remote side
            self.log("Extracting files on remote server...")
            
            extract_cmd = f"python3 {remote_script_path} {remote_zip_path} {remote_dir}"
            
            self.ssh.exec_command(f"chmod +x {remote_script_path}")
            
            # Execute the script
            self.ssh.exec_command(extract_cmd)
            
            # If we made it here, all files were transferred successfully
            transferred_files = len(files_to_compress) - error_count
            
            # Update progress to 100%
            self.update_progress("Compressed transfer complete", 100)
            
            # Clean up remote temporary files
            try:
                self.log("Cleaning up temporary files...")
                self.sftp.remove(remote_zip_path)
                self.sftp.remove(remote_script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up remote temporary files: {str(e)}")
                
        except Exception as e:
            self.log(f"Error during compressed upload: {str(e)}")
            error_count += 1
            
        finally:
            # Clean up local temporary files
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
                if 'script_path' in locals() and os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up local temporary files: {str(e)}")
                
        return total_files, transferred_files, error_count
        
    def _transfer_with_compression_download(self, remote_dir, local_dir, exclusions, 
                                          compression_level, skip_compressed, stop_check):
        """Handle downloading with compression from remote to local"""
        self.log(f"Preparing compressed download from {remote_dir} to {local_dir}")
        
        # Map compression levels to zipfile compression constants
        compression_map = {
            "fast": zipfile.ZIP_DEFLATED,
            "balanced": zipfile.ZIP_DEFLATED,
            "maximum": zipfile.ZIP_DEFLATED
        }
        
        # Map compression levels to compression values (0-9)
        level_map = {
            "fast": 1,
            "balanced": 6,
            "maximum": 9
        }
        
        # Create temporary filenames
        local_temp_zip = os.path.join(tempfile.gettempdir(), f"remote_download_{int(time.time())}.zip")
        remote_temp_zip = f"{remote_dir}/_download_temp.zip"
        remote_script_path = f"{remote_dir}/_compress_temp.py"
        
        # Initialize counters
        total_files = 0
        transferred_files = 0
        error_count = 0
        
        try:
            # Check if we need to stop before starting
            if stop_check and stop_check():
                self.log("Download stopped before starting")
                return total_files, transferred_files, error_count
                
            # Step 1: Create the compression script on the remote side
            compression_script = f"""#!/usr/bin/env python3
import os
import sys
import zipfile
import fnmatch

def compress_directory(directory, output_zip, exclusions=None, skip_compressed=False):
    # Define extensions that are already compressed
    compressed_extensions = ['.zip', '.gz', '.bz2', '.xz', '.7z', '.rar', 
                           '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.avi']
    
    # Ensure directory path ends with slash
    if not directory.endswith('/'):
        directory += '/'
    
    print(f"Scanning directory: {{directory}}")
    
    # Find all files
    files_to_compress = []
    total_files = 0
    
    for root, dirs, files in os.walk(directory):
        # Apply folder exclusions
        if exclusions:
            for exclusion in exclusions:
                for i, d in reversed(list(enumerate(dirs))):
                    rel_dir = os.path.relpath(os.path.join(root, d), directory)
                    if rel_dir == exclusion or rel_dir.startswith(exclusion + os.sep) or d == exclusion:
                        del dirs[i]
        
        for file in files:
            total_files += 1
            file_path = os.path.join(root, file)
            
            # Skip temporary files we're creating
            if file_path.endswith('_compress_temp.py') or file_path.endswith('_download_temp.zip'):
                continue
                
            # Get relative path
            rel_path = os.path.relpath(file_path, directory)
            
            # Skip excluded directories
            if exclusions:
                rel_dir = os.path.dirname(rel_path)
                skip = False
                for exclusion in exclusions:
                    if rel_dir == exclusion or rel_dir.startswith(exclusion + os.sep):
                        skip = True
                        break
                if skip:
                    print(f"Skipping excluded file: {{rel_path}}")
                    continue
            
            # Skip already compressed files if requested
            if skip_compressed:
                ext = os.path.splitext(file_path.lower())[1]
                if ext in compressed_extensions:
                    print(f"Skipping already compressed file: {{rel_path}}")
                    continue
            
            files_to_compress.append((file_path, rel_path))
    
    print(f"Found {{len(files_to_compress)}} files to compress out of {{total_files}} total files")
    
    # Create the zip file
    with zipfile.ZipFile(output_zip, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel={level_map[compression_level]}) as zipf:
        for i, (file_path, rel_path) in enumerate(files_to_compress):
            try:
                # Print progress every 10 files
                if (i + 1) % 10 == 0 or (i + 1) == len(files_to_compress):
                    print(f"Compressing files: {{i+1}}/{{len(files_to_compress)}}")
                
                zipf.write(file_path, rel_path)
                
            except Exception as e:
                print(f"Error compressing {{rel_path}}: {{str(e)}}")
    
    print(f"Compression complete. Archive created at {{output_zip}}")
    return total_files, len(files_to_compress)

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python compress.py <directory> <output_zip> [exclusions] [skip_compressed]")
        sys.exit(1)
        
    directory = sys.argv[1]
    output_zip = sys.argv[2]
    
    exclusions = None
    if len(sys.argv) > 3 and sys.argv[3] != "None":
        exclusions = sys.argv[3].split(',')
        
    skip_compressed = False
    if len(sys.argv) > 4 and sys.argv[4].lower() == "true":
        skip_compressed = True
    
    try:
        total, compressed = compress_directory(directory, output_zip, exclusions, skip_compressed)
        print(f"COMPRESS_RESULT:{{total}}:{{compressed}}")
        sys.exit(0)
    except Exception as e:
        print(f"Compression failed: {{str(e)}}")
        sys.exit(1)
"""

            # Upload the compression script
            try:
                with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as script_file:
                    script_path = script_file.name
                    script_file.write(compression_script.encode('utf-8'))
                
                self.log("Uploading compression script to remote server")
                self.sftp.put(script_path, remote_script_path)
                self.sftp.chmod(remote_script_path, 0o755)  # Make it executable
            except Exception as e:
                self.log(f"Error creating compression script: {str(e)}")
                raise
                
            # Check if we need to stop before compressing
            if stop_check and stop_check():
                self.log("Download stopped before remote compression")
                return total_files, transferred_files, error_count
                
            # Step 2: Run the compression script on the remote side
            exclusions_str = "None"
            if exclusions:
                exclusions_str = ",".join(exclusions)
                
            compress_cmd = f"python3 {remote_script_path} {remote_dir} {remote_temp_zip} {exclusions_str} {str(skip_compressed)}"
            
            self.log(f"Starting remote compression: {compress_cmd}")
            self.update_progress("Starting remote compression", 0)
            
            stdin, stdout, stderr = self.ssh.exec_command(compress_cmd)
            
            # Monitor the compression progress
            compress_total = 0
            compress_current = 0
            for line in stdout:
                line = line.strip()
                if line:
                    self.log(f"Remote: {line}")
                    
                    # Check if we should stop during compression
                    if stop_check and stop_check():
                        self.log("Download stopped during remote compression")
                        # We can't really stop the remote process easily, so we'll just return
                        return total_files, transferred_files, error_count
                    
                    # Parse progress
                    if line.startswith("Compressing files:"):
                        try:
                            # Format: "Compressing files: X/Y"
                            parts = line.split(":")[1].strip().split("/")
                            compress_current = int(parts[0])
                            compress_total = int(parts[1])
                            progress = (compress_current / compress_total) * 50
                            self.update_progress(f"Compressing files: {compress_current}/{compress_total}", progress)
                        except:
                            pass
                    elif line.startswith("COMPRESS_RESULT:"):
                        # Format: "COMPRESS_RESULT:total:compressed"
                        parts = line.split(":")[1:]
                        total_files = int(parts[0])
                        compressed_count = int(parts[1])
            
            # Check if the compression was successful
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                error_output = stderr.read().decode('utf-8')
                self.log(f"Error during remote compression: {error_output}")
                raise Exception(f"Remote compression failed with exit code {exit_code}")
                
            # Check if we need to stop before downloading
            if stop_check and stop_check():
                self.log("Download stopped before downloading archive")
                return total_files, transferred_files, error_count
                
            # Step 3: Download the compressed file
            self.log(f"Downloading compressed archive from {remote_temp_zip} to {local_temp_zip}")
            
            try:
                # Get file size for progress tracking
                remote_stat = self.sftp.stat(remote_temp_zip)
                zip_size = remote_stat.st_size
                self.log(f"Archive size: {zip_size} bytes")
                
                # Download the file
                self.sftp.get(remote_temp_zip, local_temp_zip)
                
                # Update progress
                self.update_progress("Archive downloaded, extracting files", 75)
            except Exception as e:
                self.log(f"Error downloading compressed archive: {str(e)}")
                raise
                
            # Check if we need to stop before extracting
            if stop_check and stop_check():
                self.log("Download stopped before extraction")
                return total_files, transferred_files, error_count
                
            # Step 4: Extract the zip file locally
            self.log(f"Extracting files to {local_dir}")
            
            # Ensure the target directory exists
            os.makedirs(local_dir, exist_ok=True)
            
            # Extract the files
            with zipfile.ZipFile(local_temp_zip, 'r') as zipf:
                # Get total number of items
                infolist = zipf.infolist()
                
                # Extract all files
                for i, item in enumerate(infolist):
                    # Check if we should stop during extraction
                    if i % 10 == 0 and stop_check and stop_check():
                        self.log("Download stopped during extraction")
                        return total_files, transferred_files, error_count
                        
                    # Create directory if needed
                    item_dir = os.path.dirname(os.path.join(local_dir, item.filename))
                    if item_dir:
                        os.makedirs(item_dir, exist_ok=True)
                    
                    # Extract the file
                    try:
                        zipf.extract(item, local_dir)
                        transferred_files += 1
                    except Exception as e:
                        self.log(f"Error extracting {item.filename}: {str(e)}")
                        error_count += 1
                    
                    # Update progress
                    if (i + 1) % 10 == 0 or (i + 1) == len(infolist):
                        progress = 75 + ((i + 1) / len(infolist)) * 25
                        self.update_progress(f"Extracting files: {i+1}/{len(infolist)}", progress)
            
            # Clean up remote temporary files
            try:
                self.log("Cleaning up remote temporary files")
                self.sftp.remove(remote_temp_zip)
                self.sftp.remove(remote_script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up remote temporary files: {str(e)}")
        
        except Exception as e:
            self.log(f"Error during compressed download: {str(e)}")
            error_count += 1
            
        finally:
            # Clean up local temporary files
            try:
                if os.path.exists(local_temp_zip):
                    os.unlink(local_temp_zip)
                if 'script_path' in locals() and os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up local temporary files: {str(e)}")
        
        return total_files, transferred_files, error_count