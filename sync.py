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
import random


class FolderSync:
    # Log levels
    LOG_LEVEL_ERROR = 3
    LOG_LEVEL_INFO = 2
    LOG_LEVEL_DEBUG = 1

    def __init__(
        self,
        callback=None,
        local_cache_file=None,
        remote_cache_file=None,
        max_workers=None,
        log_callback=None,
    ):
        """
        Initialize the folder sync with an optional callback for progress updates
        
        callback: function(status_message, progress_percentage, log_message)
        local_cache_file: path to file for caching local file metadata
        remote_cache_file: path to file for caching remote file metadata
        max_workers: maximum number of worker processes/threads to use (None = auto)
        log_callback: function(message) for logging
        """
        # Initialize logging first
        self.log_callback = log_callback
        self.log_level = self.LOG_LEVEL_INFO  # Default to INFO level
        
        # Then initialize other attributes
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
    
    def log(self, message, level=LOG_LEVEL_INFO):
        """Log a message if its level is greater than or equal to the current log level."""
        if level >= self.log_level:
            if self.log_callback:
                self.log_callback(message)
        else:
            print(message)
    
    def update_status(self, status):
        """Update status message using the callback if available"""
        if self.callback:
            self.callback(status_message=status)
        else:
            print(status)
    
    def update_progress(self, status_message=None, progress=None, current_directory=None):
        """Update progress and optionally status message using the callback if available
        
        Args:
            status_message: Optional status message to display
            progress: Optional progress percentage (0-100)
            current_directory: Optional current directory being scanned
        """
        if self.callback:
            # Format the display message to show both status and current directory
            display_message = ""
            
            # Add the status message if provided
            if status_message:
                display_message = status_message
            
            # Add the current directory on a new line if provided
            if current_directory:
                if display_message:
                    display_message += f"\nLocation: {current_directory}"
                else:
                    display_message = f"Location: {current_directory}"
                
            self.callback(status_message=display_message, progress=progress)
        else:
            if status_message:
                progress_str = f" - {progress}%" if progress is not None else ""
                dir_str = f"\nLocation: {current_directory}" if current_directory else ""
                print(f"{status_message}{progress_str}{dir_str}")
    
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
    
    def get_remote_file_hash(
        self, sftp, file_path, timeout=30, max_size=100 * 1024 * 1024
    ):
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

            # For very large files, use a partial hash approach if max_size is
            # set
            if max_size > 0 and file_size > max_size:
                self.log(
                    f"Using partial hash for large file {file_path} ({file_size_mb:.2f} MB)"
                )
                try:
                    with sftp.open(file_path, "rb") as f:
                        # Read first 50KB
                        start_data = f.read(50 * 1024)
                        hash_md5.update(start_data)

                        # Only try to read the end if file is large enough
                        if file_size > 100 * 1024:
                            try:
                                # Skip to the end and read last 50KB
                                f.seek(max(0, file_size - 50 * 1024))
                                end_data = f.read(50 * 1024)
                                hash_md5.update(end_data)
                            except Exception as e:
                                # If seeking fails, just use what we have plus
                                # the size
                                self.log(
                                    f"Error seeking to end of file {file_path}: {str(e)}"
                                )

                        # Add size as part of the hash to differentiate similar
                        # files
                        hash_md5.update(str(file_size).encode())
                        return hash_md5.hexdigest()
                except Exception as e:
                    self.log(
                        f"Error calculating partial hash for {file_path}: {str(e)}"
                    )
                    # Return a special marker with file size to still have some
                    # data
                    return f"partial_error_{file_size}"
        except Exception as e:
            self.log(f"Error getting file stats for {file_path}: {str(e)}")
            return f"stat_error_{str(e)}"

    def calculate_hash_batch(
        self,
        files_to_hash,
        is_remote=False,
        sftp=None,
        timeout=30,
        max_size=100 * 1024 * 1024,
    ):
        """Calculate hashes for a batch of files and return the results"""
        results = {}
        for rel_path, info in files_to_hash.items():
            if is_remote:
                hash_value = self.get_remote_file_hash(
                    sftp, info["path"], timeout=timeout, max_size=max_size
                )
            else:
                hash_value = self.get_file_hash(info["path"])
                
            results[rel_path] = hash_value
            
        return results
    
    def calculate_hashes_parallel(
        self, files_dict, is_remote=False, sftp=None, stop_check=None
    ):
        """Calculate hashes for multiple files in parallel using multiple cores"""
        if not files_dict:
            return {}
            
        # Check if we should stop
        if stop_check and stop_check():
            self.log("Hash calculation stopped by user")
            return {}

        # Identify files that need hashes calculated
        files_to_hash = {
            rel_path: info
            for rel_path, info in files_dict.items()
            if info["hash"] is None
        }
        
        if not files_to_hash:
            return {}
            
        total_files = len(files_to_hash)
        self.log(
            f"Calculating hashes for {total_files} files using {self.max_workers} workers"
        )

        # For remote files, use a more cautious sequential approach
        if is_remote:
            return self._calculate_remote_hashes_sequentially(
                files_to_hash, sftp, stop_check
            )

        # For local files, continue with parallel processing
        # Divide work into smaller batches for more frequent progress updates
        # and cancellation checks
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
                    # Force shutdown the executor
                    executor.shutdown(wait=False)
                    return results

                try:
                    # Wait for this batch with a timeout
                    try:
                        batch_results = future.result(
                            timeout=300
                        )  # 5-minute timeout per batch
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
                            progress=progress,
                        )

                except Exception as e:
                    self.log(f"Error in hash calculation batch: {str(e)}")
                    failed_files += batch_size
                    completed_batches += 1

        # Report final status
        if timeout_files > 0 or failed_files > 0:
            self.log(
                f"Hash calculation completed with {timeout_files} timeouts and {failed_files} failures"
            )
        
        # Update the original dictionary with the calculated hashes
        for rel_path, hash_value in results.items():
            files_dict[rel_path]["hash"] = hash_value

        return results

    def _calculate_remote_hashes_sequentially(
        self, files_to_hash, sftp, stop_check=None
    ):
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
        sorted_files = sorted(files_to_hash.items(), key=lambda x: x[1]["size"])

        self.log(
            f"Processing {total_files} remote files sequentially with {timeout_per_file}s timeout per file"
        )

        for rel_path, info in sorted_files:
            # Check if we should stop
            if stop_check and stop_check():
                self.log(
                    f"Remote hash calculation stopped by user after processing {processed}/{total_files} files"
                )
                break

            processed += 1
            file_size_mb = info["size"] / (1024 * 1024)
            self.log(
                f"Processing file {processed}/{total_files}: {rel_path} ({file_size_mb:.2f} MB)"
            )

            # Update progress frequently
            if self.callback:
                progress = (processed / total_files) * 100
                self.callback(
                    status_message=f"Calculating hash: {processed}/{total_files} ({skipped} skipped)",
                    progress=progress,
                )

            # Skip very large files automatically (over 100MB)
            if info["size"] > 100 * 1024 * 1024:
                self.log(
                    f"Skipping large file {rel_path} ({file_size_mb:.2f} MB) - using partial hash"
                )
                # Use partial hash (first/last 50KB + size)
                try:
                    hash_value = self.get_remote_file_hash(
                        sftp, info["path"], timeout=timeout_per_file, max_size=1
                    )  # Force partial hash
                    results[rel_path] = hash_value
                    continue
                except Exception as e:
                    self.log(f"Error calculating partial hash for {rel_path}: {str(e)}")
                    results[rel_path] = f"error_hash_{info['size']}"
                    skipped += 1
                    continue

            # For normal files, try with timeout
            try:
                hash_value = self.get_remote_file_hash(
                    sftp, info["path"], timeout=timeout_per_file
                )

                # Check if it was a timeout
                if hash_value and hash_value.startswith("timeout_partial_"):
                    skipped += 1
                    self.log(
                        f"File {rel_path} hash calculation timed out after {timeout_per_file}s"
                    )

                results[rel_path] = hash_value

            except Exception as e:
                self.log(f"Error calculating hash for {rel_path}: {str(e)}")
                results[rel_path] = f"error_hash_{info['size']}"
                skipped += 1

        self.log(
            f"Completed remote hash calculation: {processed} processed, {skipped} skipped/timeout"
        )

        # Update the original dictionary with the calculated hashes
        for rel_path, hash_value in results.items():
            if rel_path in files_to_hash:
                files_to_hash[rel_path]["hash"] = hash_value
            
        return results
    
    def load_local_metadata(self):
        """Load local file metadata from cache file"""
        if not self.local_cache_file or not os.path.exists(self.local_cache_file):
            self.log("DEBUG: No local metadata cache file found")
            return {}
        
        try:
            with open(self.local_cache_file, "r") as f:
                metadata = json.load(f)
                
            # Validate the loaded metadata
            valid_metadata = {}
            for rel_path, info in metadata.items():
                if all(key in info for key in ["path", "size", "mtime", "hash"]):
                    valid_metadata[rel_path] = info
                else:
                    self.log(f"DEBUG: Skipping invalid metadata entry for {rel_path}")
                    
            self.log(f"DEBUG: Loaded metadata for {len(valid_metadata)} local files from cache")
            return valid_metadata
        except Exception as e:
            self.log(f"Error loading local metadata cache: {str(e)}")
            return {}
    
    def save_local_metadata(self, metadata):
        """Save local file metadata to cache file"""
        if not self.local_cache_file:
            self.log("DEBUG: No local metadata cache file specified")
            return False
        
        try:
            # Create directory if it doesn't exist
            cache_dir = os.path.dirname(self.local_cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
                
            # Validate and clean metadata before saving
            valid_metadata = {}
            for rel_path, info in metadata.items():
                if all(key in info for key in ["path", "size", "mtime"]):
                    valid_metadata[rel_path] = {
                        "path": info["path"],
                        "size": info["size"],
                        "mtime": info["mtime"],
                        "hash": info.get("hash")  # Hash might be None
                    }
                else:
                    self.log(f"DEBUG: Skipping invalid metadata for {rel_path}")
                
            with open(self.local_cache_file, "w") as f:
                json.dump(valid_metadata, f)
                
            self.log(f"DEBUG: Saved metadata for {len(valid_metadata)} local files to cache")
            return True
        except Exception as e:
            self.log(f"Error saving local metadata cache: {str(e)}")
            return False
    
    def load_remote_metadata(self):
        """Load remote file metadata from cache file"""
        if not self.remote_cache_file or not os.path.exists(self.remote_cache_file):
            self.log("DEBUG: No remote metadata cache file found")
            return {}
        
        try:
            with open(self.remote_cache_file, "r") as f:
                metadata = json.load(f)
                
            # Validate the loaded metadata
            valid_metadata = {}
            for rel_path, info in metadata.items():
                if all(key in info for key in ["path", "size", "mtime", "hash"]):
                    valid_metadata[rel_path] = info
                else:
                    self.log(f"DEBUG: Skipping invalid metadata entry for {rel_path}")
                    
            self.log(f"DEBUG: Loaded metadata for {len(valid_metadata)} remote files from cache")
            return valid_metadata
        except Exception as e:
            self.log(f"Error loading remote metadata cache: {str(e)}")
            return {}
    
    def save_remote_metadata(self, metadata):
        """Save remote file metadata to cache file"""
        if not self.remote_cache_file:
            self.log("DEBUG: No remote metadata cache file specified")
            return False
        
        try:
            # Create directory if it doesn't exist
            cache_dir = os.path.dirname(self.remote_cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
                
            # Validate and clean metadata before saving
            valid_metadata = {}
            for rel_path, info in metadata.items():
                if all(key in info for key in ["path", "size", "mtime"]):
                    valid_metadata[rel_path] = {
                        "path": info["path"],
                        "size": info["size"],
                        "mtime": info["mtime"],
                        "hash": info.get("hash")  # Hash might be None
                    }
                else:
                    self.log(f"DEBUG: Skipping invalid metadata for {rel_path}")
                
            with open(self.remote_cache_file, "w") as f:
                json.dump(valid_metadata, f)
                
            self.log(f"DEBUG: Saved metadata for {len(valid_metadata)} remote files to cache")
            return True
        except Exception as e:
            self.log(f"Error saving remote metadata cache: {str(e)}")
            return False
    
    def list_local_files(
        self,
        local_dir,
        ignore_patterns=None,
        extension_filters=None,
        filter_mode="include",
        folder_exclusions=None,
        calculate_hashes=False,
        stop_check=None,
        use_cache_only=False,
    ):
        """List files in local directory with metadata"""
        results = {}
        self.local_metadata = {}  # Reset local metadata

        # Try to load cached metadata first
        cached_metadata = {}
        if use_cache_only or not calculate_hashes:
            cached_metadata = self.load_local_metadata()
        if use_cache_only and cached_metadata:
            self.log("Using cached local metadata only")
            self.local_metadata = cached_metadata
            return cached_metadata

        try:
            # Normalize extension filters - ensure they start with a dot and remove any duplicates
            if extension_filters:
                normalized_filters = set()
                for ext in extension_filters:
                    # Remove any leading/trailing whitespace
                    ext = ext.strip()
                    # Add a dot if it doesn't start with one
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    normalized_filters.add(ext.lower())
                extension_filters = list(normalized_filters)
                self.log(f"DEBUG: Normalized extension filters: {extension_filters}")

            for root, dirs, files in os.walk(local_dir):
                if stop_check and stop_check():
                    break

                # Update scanning status
                rel_root = os.path.relpath(root, local_dir)
                if rel_root == ".":
                    rel_root = "/"
                self.update_status(f"Scanning local directory: {rel_root}")

                # Apply folder exclusions
                if folder_exclusions:
                    dirs_to_remove = []
                    for i, d in enumerate(dirs):
                        # Get the full relative path of this directory
                        dir_rel_path = os.path.normpath(os.path.join(rel_root, d)).replace("\\", "/")
                        # Check if this directory or any of its parents should be excluded
                        for exclusion in folder_exclusions:
                            exclusion = os.path.normpath(exclusion).replace("\\", "/")
                            if (dir_rel_path == exclusion or 
                                dir_rel_path.startswith(exclusion + "/") or 
                                d == exclusion or
                                ("/" + dir_rel_path + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Excluding directory: {dir_rel_path} (matches exclusion {exclusion})")
                                dirs_to_remove.append(i)
                                break
                                
                    # Remove excluded directories in reverse order to maintain indices
                    for i in sorted(dirs_to_remove, reverse=True):
                        del dirs[i]

                for file in files:
                    if stop_check and stop_check():
                            break
                    
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, local_dir)

                    # Check if file is in an excluded directory
                    if folder_exclusions:
                        file_dir = os.path.dirname(rel_path).replace("\\", "/")
                        skip_file = False
                        for exclusion in folder_exclusions:
                            exclusion = os.path.normpath(exclusion).replace("\\", "/")
                            if (file_dir == exclusion or 
                                file_dir.startswith(exclusion + "/") or
                                ("/" + file_dir + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Skipping file in excluded directory: {rel_path}")
                                skip_file = True
                                break
                        if skip_file:
                            continue

                    # Check ignore patterns
                    if ignore_patterns and any(fnmatch(rel_path, p) for p in ignore_patterns):
                        continue
                    
                    # Apply extension filters
                    if extension_filters:
                        file_ext = os.path.splitext(file)[1].lower()
                        # Add a dot if it doesn't have one
                        if file_ext and not file_ext.startswith('.'):
                            file_ext = '.' + file_ext
                            
                        if filter_mode == "include":
                            if file_ext not in extension_filters:
                                self.log(f"Skipping {rel_path} - extension {file_ext} not in include list {extension_filters}")
                            continue
                        elif filter_mode == "exclude":
                            if file_ext in extension_filters:
                                self.log(f"Skipping {rel_path} - extension {file_ext} in exclude list {extension_filters}")
                        continue
                    
                    try:
                        stat_info = os.stat(full_path)
                        file_info = {
                            "path": rel_path,
                            "size": stat_info.st_size,
                            "mtime": stat_info.st_mtime,
                            "hash": None,
                        }

                        # Check if we have valid cached metadata
                        cached_info = cached_metadata.get(rel_path)
                        if cached_info and abs(cached_info["mtime"] - file_info["mtime"]) < 2:
                            file_info["hash"] = cached_info["hash"]
                            self.log(f"Using cached hash for {rel_path}")
                        elif calculate_hashes:
                            file_info["hash"] = self._calculate_file_hash(full_path)
                            self.log(f"Calculated new hash for {rel_path}")

                        results[rel_path] = file_info
                        self.local_metadata[rel_path] = file_info

                    except Exception as e:
                        self.log(f"Error processing local file {rel_path}: {str(e)}")

            # Save metadata if we calculated any new hashes
            if calculate_hashes:
                self.save_local_metadata(self.local_metadata)
                self.log(f"Saved metadata for {len(self.local_metadata)} local files")

            return results
            
        except Exception as e:
            self.log(f"Error listing local files: {str(e)}")
            return {}
    
    def list_remote_files(
        self,
        remote_dir,
        ignore_patterns=None,
        extension_filters=None,
        filter_mode="include",
        folder_exclusions=None,
        calculate_hashes=False,
        stop_check=None,
        use_cache_only=False,
    ):
        """List files in remote directory with metadata"""
        results = {}
        self.remote_metadata = {}  # Reset remote metadata

        # Try to load cached metadata first
        cached_metadata = {}
        if use_cache_only or not calculate_hashes:
            cached_metadata = self.load_remote_metadata()
        if use_cache_only and cached_metadata:
            self.log("Using cached remote metadata only")
            self.remote_metadata = cached_metadata
            return cached_metadata

        try:
            # Normalize extension filters - ensure they start with a dot and remove any duplicates
            if extension_filters:
                normalized_filters = set()
                for ext in extension_filters:
                    # Remove any leading/trailing whitespace
                    ext = ext.strip()
                    # Add a dot if it doesn't start with one
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    normalized_filters.add(ext.lower())
                extension_filters = list(normalized_filters)
                self.log(f"DEBUG: Normalized extension filters: {extension_filters}")

            for root, dirs, files in self.sftp_walk(remote_dir):
                if stop_check and stop_check():
                                break
                                
                # Update scanning status
                rel_root = os.path.relpath(root, remote_dir)
                if rel_root == ".":
                    rel_root = "/"
                self.update_status(f"Scanning remote directory: {rel_root}")

                # Apply folder exclusions - check full relative path
                if folder_exclusions:
                    dirs_to_remove = []
                    for i, d in enumerate(dirs):
                        # Get the full relative path of this directory
                        dir_rel_path = os.path.normpath(os.path.join(rel_root, d)).replace("\\", "/")
                        # Check if this directory or any of its parents should be excluded
                        for exclusion in folder_exclusions:
                            exclusion = os.path.normpath(exclusion).replace("\\", "/")
                            if (dir_rel_path == exclusion or 
                                dir_rel_path.startswith(exclusion + "/") or 
                                d == exclusion or
                                ("/" + dir_rel_path + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Excluding directory: {dir_rel_path} (matches exclusion {exclusion})")
                                dirs_to_remove.append(i)
                                break
                                
                    # Remove excluded directories in reverse order to maintain indices
                    for i in sorted(dirs_to_remove, reverse=True):
                        del dirs[i]

                for file in files:
                    if stop_check and stop_check():
                                    break
                            
                    full_path = os.path.join(root, file).replace("\\", "/")
                    rel_path = os.path.relpath(full_path, remote_dir).replace("\\", "/")
                    
                    # Check if file is in an excluded directory
                    if folder_exclusions:
                        file_dir = os.path.dirname(rel_path).replace("\\", "/")
                        skip_file = False
                        for exclusion in folder_exclusions:
                            exclusion = os.path.normpath(exclusion).replace("\\", "/")
                            if (file_dir == exclusion or 
                                file_dir.startswith(exclusion + "/") or
                                ("/" + file_dir + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Skipping file in excluded directory: {rel_path}")
                                skip_file = True
                                break
                        if skip_file:
                            continue

                    # Check ignore patterns
                    if ignore_patterns and any(fnmatch(rel_path, p) for p in ignore_patterns):
                        continue

                    # Apply extension filters
                    if extension_filters:
                        file_ext = os.path.splitext(file)[1].lower()
                        # Add a dot if it doesn't have one
                        if file_ext and not file_ext.startswith('.'):
                            file_ext = '.' + file_ext
                            
                        if filter_mode == "include":
                            if file_ext not in extension_filters:
                                self.log(f"Skipping {rel_path} - extension {file_ext} not in include list {extension_filters}")
                                continue
                        elif filter_mode == "exclude":
                            if file_ext in extension_filters:
                                self.log(f"Skipping {rel_path} - extension {file_ext} in exclude list {extension_filters}")
                            continue

                    try:
                        stat_info = self.sftp.lstat(full_path)
                        file_info = {
                            "path": rel_path,
                            "size": stat_info.st_size,
                            "mtime": stat_info.st_mtime,
                            "hash": None,
                        }

                        # Check if we have valid cached metadata
                        cached_info = cached_metadata.get(rel_path)
                        if cached_info and abs(cached_info["mtime"] - file_info["mtime"]) < 2:
                            file_info["hash"] = cached_info["hash"]
                            self.log(f"Using cached hash for {rel_path}")
                        elif calculate_hashes:
                            file_info["hash"] = self._calculate_remote_file_hash(full_path)
                            self.log(f"Calculated new hash for {rel_path}")

                        results[rel_path] = file_info
                        self.remote_metadata[rel_path] = file_info

                    except Exception as e:
                        self.log(f"Error processing remote file {rel_path}: {str(e)}")

            # Save metadata if we calculated any new hashes
            if calculate_hashes:
                self.save_remote_metadata(self.remote_metadata)
                self.log(f"Saved metadata for {len(self.remote_metadata)} remote files")

            return results
            
        except Exception as e:
            self.log(f"Error listing remote files: {str(e)}")
            return {}
    
    def sync_with_existing_connection(
        self,
        ssh_client,
        sftp_client,
        local_dir,
        remote_dir,
        bidirectional=True,
        sync_mode="both",
        extension_filters=None,
        filter_mode="include",
        stop_check=None,
        folder_exclusions=None,
        content_only_compare=False,
        transfer_method="sftp",
        verbose_logging=True,
        force_sync=False,
        use_cache_only=False,
    ):
        """
        Sync files using an existing SFTP connection
        
        Args:
            ssh_client: Paramiko SSH client object
            sftp_client: Paramiko SFTP client object
            local_dir: Local directory path
            remote_dir: Remote directory path
            bidirectional: Whether to sync in both directions
            sync_mode: Direction of sync ('both', 'to_remote', 'to_local')
            extension_filters: List of file extensions to filter
            filter_mode: How to apply extension filters ('include' or 'exclude')
            stop_check: Function to check if sync should be stopped
            folder_exclusions: List of folders to exclude
            content_only_compare: Whether to compare only file contents
            transfer_method: Method to use for file transfer ('sftp' or 'scp')
            verbose_logging: Whether to log detailed information
            force_sync: Whether to force sync all files
            use_cache_only: Whether to only use cached metadata
            
        Returns:
            True if sync was successful, False otherwise
        """
        try:
            # Store SFTP client for use in other methods
            self.sftp = sftp_client

            # Local and remote directory should exist
            if not os.path.isdir(local_dir):
                self.log(f"Local directory does not exist: {local_dir}")
                return False

            # Ensure local directory path ends with a slash for consistent path
            # manipulation
            if not local_dir.endswith(os.path.sep):
                local_dir = local_dir + os.path.sep

            # Ensure remote directory path ends with a slash for consistent path
            # manipulation
            if not remote_dir.endswith("/"):
                remote_dir = remote_dir + "/"

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
            if verbose_logging:
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
                self.log(
                    "FORCE SYNC ENABLED: All files will be transferred regardless of comparison"
                )

            # Log cache usage
            if use_cache_only:
                self.log(
                    "USING CACHE ONLY: Only checking files in the cache (faster, but new files won't be detected)"
                )

            # Create .synccache directory if it doesn't exist
            cache_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), ".synccache"
            )
            try:
                os.makedirs(cache_dir, exist_ok=True)
                self.log(f"Cache directory verified/created at: {cache_dir}")
            except Exception as e:
                self.log(f"Warning: Could not create cache directory: {str(e)}")

            # Always calculate hashes during initial scan if not using force_sync
            # This ensures we have valid metadata for comparison
            should_calculate_hashes = not force_sync or content_only_compare

            # Scan directories
            self.update_status("Scanning local directory...")
            local_files = self.list_local_files(
                local_dir, 
                extension_filters=extension_filters, 
                filter_mode=filter_mode,
                folder_exclusions=folder_exclusions,
                calculate_hashes=should_calculate_hashes,
                stop_check=stop_check,
                use_cache_only=use_cache_only,
            )
            
            # Check if stop was requested
            if stop_check and stop_check():
                self.log("Synchronization stopped before scanning remote directory")
                return False
                
            self.update_status("Scanning remote directory...")
            try:
                remote_files = self.list_remote_files(
                    remote_dir, 
                    extension_filters=extension_filters, 
                    filter_mode=filter_mode,
                    folder_exclusions=folder_exclusions,
                    calculate_hashes=should_calculate_hashes,
                    stop_check=stop_check,
                    use_cache_only=use_cache_only,
                )
            except Exception as e:
                self.log(f"Error scanning remote directory: {str(e)}")
                self.log(f"Traceback: {traceback.format_exc()}")
                return False

            # Log files that exist on remote but not on local
            remote_only_files = [path for path in remote_files if path not in local_files]
            if remote_only_files:
                self.log(
                    f"Found {len(remote_only_files)} files on remote that don't exist locally:"
                )
                for i, path in enumerate(
                    remote_only_files[:10]
                ):  # Show just first 10 to avoid log spam
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
                    local_files,
                    remote_files,
                    local_dir,
                    remote_dir,
                    force_sync=force_sync,
                    content_only_compare=content_only_compare,
                    stop_check=stop_check,
                )
                sync_success = sync_success and to_remote_success
                    
            # Remote to local sync if needed
            if sync_mode in ["both", "to_local"]:
                to_local_success = self._sync_remote_to_local(
                    remote_files,
                    local_files,
                    remote_dir,
                    local_dir,
                    force_sync=force_sync,
                    content_only_compare=content_only_compare,
                    stop_check=stop_check,
                )
                sync_success = sync_success and to_local_success
                
            # Final stop check
            if stop_check and stop_check():
                return False
                
            # Save metadata cache if sync was successful
            if sync_success:
                self.save_local_metadata(local_files)
                self.save_remote_metadata(remote_files)
                    
            self.update_status("Synchronization completed")
            self.update_progress(100)
                
            return True
                
        except Exception as e:
            self.log(f"Error during sync: {str(e)}")
            self.log(f"Traceback: {traceback.format_exc()}")
            return False
    
    def sync_directories(
        self,
        host,
        port,
        username,
        password,
        local_dir,
        remote_dir,
        bidirectional=True,
        sync_mode="both",
        extension_filters=None,
        filter_mode="include",
        stop_check=None,
        folder_exclusions=None,
        content_only_compare=False,
        transfer_method="sftp",
        verbose_logging=True,
        force_sync=False,
        use_cache_only=False,
    ):
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
                ssh_client,
                sftp_client,
                local_dir,
                remote_dir,
                bidirectional,
                sync_mode,
                extension_filters,
                filter_mode,
                stop_check,
                folder_exclusions,
                content_only_compare,
                transfer_method,
                verbose_logging,
                force_sync,
                use_cache_only,
            )

        except Exception as e:
            error_msg = f"Error during synchronization: {str(e)}"
            self.log(error_msg)
            traceback.print_exc()
            return False
    
        finally:
            # Close connections
            try:
                if "sftp_client" in locals():
                    sftp_client.close()
                if "ssh_client" in locals():
                    ssh_client.close()
            except:
                pass

    def _sync_local_to_remote(
        self,
        local_files,
        remote_files,
        local_dir,
        remote_dir,
        force_sync=False,
        content_only_compare=False,
        stop_check=None,
    ):
        """Sync local files to remote"""
        self.log("DEBUG: Starting local to remote sync with parameters:")
        self.log(f"DEBUG: force_sync: {force_sync}")
        self.log(f"DEBUG: content_only_compare: {content_only_compare}")
        self.log(f"DEBUG: Number of local files: {len(local_files)}")
        self.log(f"DEBUG: Number of remote files: {len(remote_files)}")

        total_to_sync = 0
        need_sync = []

        # First pass - identify files that need syncing
        self.update_progress(status_message="Comparing files", progress=0)
        for rel_path, local_info in local_files.items():
            if stop_check and stop_check():
                self.log("Sync stopped by user request during file comparison")
                return 0

            # Check if file exists remotely
            remote_info = remote_files.get(rel_path)
            
            # Log file comparison
            self.log(f"DEBUG: Comparing local file: {rel_path}")
            self.log(f"DEBUG: Remote file exists: {remote_info is not None}")
            
            if force_sync:
                self.log(f"DEBUG: Force sync enabled - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
                continue

            # If remote file doesn't exist, it needs to be synced
            if not remote_info:
                self.log(f"DEBUG: Remote file doesn't exist - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
                continue

            # Compare files using _files_differ method
            if self._files_differ(
                local_info,
                remote_info,
                content_only_compare=content_only_compare,
                force_sync=force_sync,
            ):
                self.log(f"DEBUG: Files differ - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
            else:
                self.log(f"DEBUG: Files are identical - skipping {rel_path}")

        # If no files need syncing, return early
        if total_to_sync == 0:
            self.log("DEBUG: No files need to be synced from local to remote")
            return 0

        self.log(f"DEBUG: Found {total_to_sync} files that need to be synced to remote")

        # Second pass - perform the actual sync
        files_synced = 0
        for rel_path in need_sync:
            if stop_check and stop_check():
                self.log("Sync stopped by user request during file transfer")
                break

            local_info = local_files[rel_path]
            local_path = os.path.join(local_dir, local_info["path"])
            remote_path = os.path.join(remote_dir, rel_path).replace("\\", "/")

            try:
                # Ensure remote directory exists
                remote_dir_path = os.path.dirname(remote_path)
                if remote_dir_path:
                    try:
                        self.sftp.stat(remote_dir_path)
                    except FileNotFoundError:
                        self.log(f"DEBUG: Creating remote directory: {remote_dir_path}")
                        self._makedirs(remote_dir_path)

                # Transfer the file
                self.log(f"DEBUG: Transferring file to remote: {rel_path}")
                self.update_progress(
                    status_message=f"Transferring to remote ({files_synced + 1}/{total_to_sync})",
                    current_directory=os.path.dirname(rel_path) or "/"
                )
                self.sftp.put(local_path, remote_path)
                
                # Update remote metadata after successful transfer
                remote_stat = self.sftp.stat(remote_path)
                remote_files[rel_path] = {
                    "path": rel_path,
                    "size": remote_stat.st_size,
                    "mtime": remote_stat.st_mtime,
                    "hash": local_info.get("hash")  # Use local hash since content is identical
                }
                
                files_synced += 1
                
                if files_synced % 10 == 0:
                    self.log(f"DEBUG: Synced {files_synced}/{total_to_sync} files to remote")

            except Exception as e:
                self.log(f"Error syncing file {rel_path} to remote: {str(e)}")
                continue

        self.log(f"DEBUG: Successfully synced {files_synced}/{total_to_sync} files to remote")
        return files_synced

    def _sync_remote_to_local(
        self,
        remote_files,
        local_files,
        remote_dir,
        local_dir,
        force_sync=False,
        content_only_compare=False,
        stop_check=None,
    ):
        """Sync remote files to local"""
        self.log("DEBUG: Starting remote to local sync with parameters:")
        self.log(f"DEBUG: force_sync: {force_sync}")
        self.log(f"DEBUG: content_only_compare: {content_only_compare}")
        self.log(f"DEBUG: Number of remote files: {len(remote_files)}")
        self.log(f"DEBUG: Number of local files: {len(local_files)}")

        total_to_sync = 0
        need_sync = []

        # First pass - identify files that need syncing
        self.update_progress(status_message="Comparing files", progress=0)
        for rel_path, remote_info in remote_files.items():
            if stop_check and stop_check():
                self.log("Sync stopped by user request during file comparison")
                return 0

            # Check if file exists locally
            local_info = local_files.get(rel_path)
            
            # Log file comparison
            self.log(f"DEBUG: Comparing remote file: {rel_path}")
            self.log(f"DEBUG: Local file exists: {local_info is not None}")
            
            if force_sync:
                self.log(f"DEBUG: Force sync enabled - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
                continue

            # If local file doesn't exist, it needs to be synced
            if not local_info:
                self.log(f"DEBUG: Local file doesn't exist - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
                continue

            # Compare files using _files_differ method
            if self._files_differ(
                remote_info,
                local_info,
                content_only_compare=content_only_compare,
                force_sync=force_sync,
            ):
                self.log(f"DEBUG: Files differ - will sync {rel_path}")
                need_sync.append(rel_path)
                total_to_sync += 1
            else:
                self.log(f"DEBUG: Files are identical - skipping {rel_path}")

        # If no files need syncing, return early
        if total_to_sync == 0:
            self.log("DEBUG: No files need to be synced from remote to local")
            return 0

        self.log(f"DEBUG: Found {total_to_sync} files that need to be synced to local")

        # Second pass - perform the actual sync
        files_synced = 0
        for rel_path in need_sync:
            if stop_check and stop_check():
                self.log("Sync stopped by user request during file transfer")
                break

            remote_info = remote_files[rel_path]
            remote_path = os.path.join(remote_dir, remote_info["path"]).replace("\\", "/")
            local_path = os.path.join(local_dir, rel_path)

            try:
                # Ensure local directory exists
                local_dir_path = os.path.dirname(local_path)
                if local_dir_path:
                    os.makedirs(local_dir_path, exist_ok=True)
                    self.log(f"DEBUG: Created local directory: {local_dir_path}")

                # Transfer the file
                self.log(f"DEBUG: Transferring file to local: {rel_path}")
                self.update_progress(
                    status_message=f"Transferring to local ({files_synced + 1}/{total_to_sync})",
                    current_directory=os.path.dirname(rel_path) or "/"
                )
                self.sftp.get(remote_path, local_path)
                
                # Update local metadata after successful transfer
                local_stat = os.stat(local_path)
                local_files[rel_path] = {
                    "path": rel_path,
                    "size": local_stat.st_size,
                    "mtime": local_stat.st_mtime,
                    "hash": remote_info.get("hash")  # Use remote hash since content is identical
                }
                
                files_synced += 1
                
                if files_synced % 10 == 0:
                    self.log(f"DEBUG: Synced {files_synced}/{total_to_sync} files to local")

            except Exception as e:
                self.log(f"Error syncing file {rel_path} to local: {str(e)}")
                continue

        self.log(f"DEBUG: Successfully synced {files_synced}/{total_to_sync} files to local")
        return files_synced

    def _files_differ(
        self,
        file1_info,
        file2_info,
        content_only_compare=False,
        force_sync=False,
    ):
        """Compare two files to determine if they differ
        
        Args:
            file1_info: Dictionary with file1's metadata
            file2_info: Dictionary with file2's metadata
            content_only_compare: If True, only compare file hashes
            force_sync: If True, always consider files different
            
        Returns:
            True if files differ, False if they are the same
        """
        if force_sync:
            return True

        # Log comparison parameters for debugging
        self.log(f"DEBUG: Comparing files:")
        self.log(f"DEBUG: File 1: size={file1_info['size']}, mtime={file1_info['mtime']}, hash={file1_info.get('hash')}")
        self.log(f"DEBUG: File 2: size={file2_info['size']}, mtime={file2_info['mtime']}, hash={file2_info.get('hash')}")
        
        # First check if we have valid hashes for both files
        hash1 = file1_info.get("hash")
        hash2 = file2_info.get("hash")
        
        if hash1 is not None and hash2 is not None:
            # If we have hashes, use them for comparison regardless of content_only_compare
            # This is the most accurate way to compare files
            files_differ = hash1 != hash2
            self.log(f"DEBUG: Using hash comparison: {'different' if files_differ else 'same'}")
            return files_differ
            
        # If we don't have hashes, fall back to size and time comparison
        # Allow for small floating point differences in mtime (2 seconds)
        # and small size differences (2 bytes) to account for system variations
        size_differs = abs(file1_info["size"] - file2_info["size"]) >= 2
        time_differs = abs(file1_info["mtime"] - file2_info["mtime"]) >= 2
        
        self.log(f"DEBUG: Size difference: {abs(file1_info['size'] - file2_info['size'])} bytes")
        self.log(f"DEBUG: Time difference: {abs(file1_info['mtime'] - file2_info['mtime'])} seconds")
        
        # If content_only_compare is True and we don't have hashes, we should calculate them
        if content_only_compare and not (hash1 and hash2):
            self.log("DEBUG: Content-only comparison requested but missing hashes")
            # We'll be more strict with size/time comparison in this case
            return size_differs or time_differs
            
        # For normal comparison, if either size or time differs significantly, 
        # files are considered different
        files_differ = size_differs or time_differs
        self.log(f"DEBUG: Using size/time comparison: {'different' if files_differ else 'same'}")
        return files_differ

    def _create_remote_dirs(self, sftp, path):
        """
        Create remote directory and all parent directories as needed

        sftp: SFTP client
        path: Remote directory path to create
        """
        if path == "/" or not path:
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

    def transfer_directory(
        self,
        host,
        port,
        username,
        password,
        source_dir,
        dest_dir,
        direction,
        folder_exclusions=None,
        stop_check=None,
        use_compression=False,
        compression_level="balanced",
        skip_compressed=True,
        extract_archives=True,
    ):
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
        - extract_archives: Whether to extract compressed archives on the destination (True) or keep them as-is (False)

        Returns:
        - (total_files, transferred_files, error_count)
        """
        self.log(f"Starting file transfer from {source_dir} to {dest_dir}")
        if use_compression:
            self.log(
                f"Using compression (level: {compression_level}, skip compressed: {skip_compressed})"
            )

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
                        source_dir,
                        dest_dir,
                        exclusions,
                        compression_level,
                        skip_compressed,
                        stop_check,
                        extract_archives,
                    )
                else:
                    # Download with compression
                    return self._transfer_with_compression_download(
                        source_dir,
                        dest_dir,
                        exclusions,
                        compression_level,
                        skip_compressed,
                        stop_check,
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
                            remote_path = os.path.join(dest_dir, relative_path).replace(
                                "\\", "/"
                            )
                            files_to_transfer.append((local_path, remote_path))
                            total_files += 1
                else:
                    # Remote source to local destination
                    self._walk_remote_dir(
                        source_dir, dest_dir, files_to_transfer, exclusions, [0]
                    )
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
                        self.update_progress(
                            f"Transferring file {i+1}/{total_files}", progress
                        )

                    except Exception as e:
                        self.log(f"Error transferring file {src_path}: {str(e)}")
                        errors.append((src_path, str(e)))
                        error_count += 1

        except Exception as e:
            self.log(f"Transfer process error: {str(e)}")
            error_count += 1

        finally:
            # Close connections
            if hasattr(self, "sftp") and self.sftp:
                self.sftp.close()
            if hasattr(self, "ssh") and self.ssh:
                self.ssh.close()

            self.log(
                f"Transfer complete: {transferred_files} of {total_files} files transferred with {error_count} errors"
            )

        return total_files, transferred_files, error_count

    def _transfer_with_compression_upload(
        self,
        local_dir,
        remote_dir,
        exclusions,
        compression_level,
        skip_compressed,
        stop_check,
        extract_archives=True,
    ):
        """Handle uploading with compression from local to remote"""
        # Normalize the local directory path for consistent handling
        local_dir = os.path.normpath(local_dir)
        self.log(f"Preparing compressed upload from {local_dir} to {remote_dir}")
        self.log(f"DEBUG: Normalized local path: {local_dir}")
        
        # Add debug log to check if the directory exists
        if not os.path.exists(local_dir):
            self.log(f"ERROR: Local directory does not exist: {local_dir}")
            return 0, 0, 0
        elif not os.path.isdir(local_dir):
            self.log(f"ERROR: Path exists but is not a directory: {local_dir}")
            return 0, 0, 0
        else:
            self.log(f"DEBUG: Local directory exists: {local_dir}")
            
        # Try to list the directory contents to verify accessibility
        try:
            dir_contents = os.listdir(local_dir)
            self.log(f"DEBUG: Directory contains {len(dir_contents)} items")
            if len(dir_contents) == 0:
                self.log("WARNING: Local directory is empty")
        except Exception as e:
            self.log(f"ERROR: Cannot read directory contents: {str(e)}")
            return 0, 0, 0

        # Map compression levels to zipfile compression constants
        compression_map = {
            "fast": zipfile.ZIP_DEFLATED,
            "balanced": zipfile.ZIP_DEFLATED,
            "maximum": zipfile.ZIP_DEFLATED,
        }

        # Map compression levels to compression values (0-9)
        level_map = {"fast": 1, "balanced": 6, "maximum": 9}

        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
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
            compressed_extensions = {
                ".zip",
                ".gz",
                ".bz2",
                ".xz",
                ".7z",
                ".rar",
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".mp3",
                ".mp4",
                ".avi",
            }
            
            self.log(f"DEBUG: Starting local directory scan on {local_dir}")
            self.log(f"DEBUG: Skip compressed files setting: {skip_compressed}")
            
            total_found_files = 0
            skipped_compressed_count = 0

            for root, dirs, files in os.walk(local_dir):
                # Check if we need to stop
                if stop_check and stop_check():
                    self.log("Upload stopped during directory scan")
                    return total_files, transferred_files, error_count
                
                rel_root = os.path.relpath(root, local_dir)
                if rel_root == '.':
                    rel_root = ''
                
                # Apply exclusions
                dirs_to_remove = []
                for i, d in enumerate(dirs):
                    # Check if directory should be excluded
                    for exclusion in exclusions:
                        dir_path = os.path.join(rel_root, d).replace("\\", "/")
                        if dir_path == exclusion or dir_path.startswith(exclusion + "/") or d == exclusion:
                            self.log(f"DEBUG: Skipping excluded directory: {dir_path}")
                            dirs_to_remove.append(i)
                            break
                
                # Remove excluded directories in reverse order to maintain indices
                for i in sorted(dirs_to_remove, reverse=True):
                    del dirs[i]
                
                self.log(f"DEBUG: Found {len(files)} files in directory {root}")
                total_found_files += len(files)

                # Process files in this directory
                for file in files:
                    local_path = os.path.join(root, file)
                    relative_path = os.path.relpath(local_path, local_dir)

                    # Skip files that are already compressed if needed
                    _, ext = os.path.splitext(local_path.lower())
                    if skip_compressed and ext in compressed_extensions:
                        self.log(f"DEBUG: Skipping already compressed file: {relative_path}")
                        skipped_compressed_count += 1
                        continue

                    files_to_compress.append((local_path, relative_path))

                    total_files += 1
            
            self.log(f"DEBUG: Directory scan complete. Found {total_found_files} total files")
            self.log(f"DEBUG: Skipped {skipped_compressed_count} compressed files")
            self.log(f"DEBUG: Added {total_files} files to compress")

            # Check if we have files to compress
            if not files_to_compress:
                self.log("No files to compress and transfer")
                if total_found_files > 0 and skipped_compressed_count > 0:
                    self.log("WARNING: All files were skipped because they have compressed extensions.")
                    self.log("WARNING: To transfer these files, uncheck 'Skip Already Compressed Files'")
                elif total_found_files == 0:
                    self.log("WARNING: No files found in the source directory")
                return total_files, 0, 0

            # Check if we need to stop before compressing
            if stop_check and stop_check():
                self.log("Upload stopped before compression")
                return total_files, transferred_files, error_count

            # Step 2: Create a ZIP file with all the files
            self.log(f"Compressing {len(files_to_compress)} files...")

            with zipfile.ZipFile(
                temp_zip_path,
                "w",
                compression=compression_map[compression_level],
                compresslevel=level_map[compression_level],
            ) as zipf:

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
                        self.update_progress(
                            f"Compressing file {i+1}/{len(files_to_compress)}", progress
                        )

                    except Exception as e:
                        self.log(f"Error compressing {rel_path}: {str(e)}")

            # Get the size of the zip file for progress tracking
            zip_size = os.path.getsize(temp_zip_path)
            self.log(f"Compressed archive size: {zip_size} bytes")

            # Check if we need to stop before uploading
            if stop_check and stop_check():
                self.log("Upload stopped after compression")
                return total_files, transferred_files, error_count

            # Upload the compressed archive to the remote server
            if extract_archives:
            # Step 3: Create a temporary script to extract the zip on the remote side
                with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as script_file:
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
                script_file.write(script_content.encode("utf-8"))

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
                self.sftp.put(temp_zip_path, remote_zip_path)
            else:
                    # If we're not extracting, upload the zip file with a proper name
                    # Create a zip filename based on the source directory name
                    zip_filename = os.path.basename(os.path.normpath(local_dir)) + ".zip"
                    remote_zip_path = os.path.join(remote_dir, zip_filename).replace("\\", "/")
                    self.log(f"Uploading compressed archive to {remote_zip_path} (will not be extracted)")
                    
                    # Check if we need to stop before uploading zip
                    if stop_check and stop_check():
                        self.log("Upload stopped before uploading zip")
                        return total_files, transferred_files, error_count

            # Upload with progress tracking
            def progress_callback(bytes_so_far):
                return self.update_progress(
                    f"Uploading archive: {bytes_so_far/zip_size*100:.1f}%",
                    50 + (bytes_so_far / zip_size) * 25,
                )

            try:
                # For progress tracking, we need to implement our own put function
                # or use a third-party library, since paramiko doesn't have built-in progress
                # callback. For now, we'll just update after the upload.
                self.sftp.put(temp_zip_path, remote_zip_path)
            except Exception as e:
                self.log(f"Error uploading compressed archive: {str(e)}")

            # Update progress after upload
            if extract_archives:
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
            else:
                self.update_progress("Archive uploaded successfully", 100)
                self.log("Upload complete, zip file preserved on remote server.")

            # If we made it here, all files were transferred successfully
            transferred_files = len(files_to_compress) - error_count

            # Update progress to 100%
            self.update_progress("Compressed transfer complete", 100)

            # Clean up remote temporary files
            try:
                self.log("Cleaning up temporary files...")
                if extract_archives:
                    self.sftp.remove(remote_script_path)
                    self.sftp.remove(remote_zip_path)
            except Exception as e:
                self.log(
                    f"Warning: Could not clean up remote temporary files: {str(e)}"
                )

        except Exception as e:
            self.log(f"Error during compressed upload: {str(e)}")
            error_count += 1

        finally:
            # Clean up local temporary files
            try:
                if os.path.exists(temp_zip_path):
                    os.unlink(temp_zip_path)
                if "script_path" in locals() and os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up local temporary files: {str(e)}")

        return total_files, transferred_files, error_count

    def _transfer_with_compression_download(
        self,
        remote_dir,
        local_dir,
        exclusions,
        compression_level,
        skip_compressed,
        stop_check,
    ):
        """Handle downloading with compression from remote to local"""
        self.log(f"Preparing compressed download from {remote_dir} to {local_dir}")

        # Map compression levels to zipfile compression constants
        compression_map = {
            "fast": zipfile.ZIP_DEFLATED,
            "balanced": zipfile.ZIP_DEFLATED,
            "maximum": zipfile.ZIP_DEFLATED,
        }

        # Map compression levels to compression values (0-9)
        level_map = {"fast": 1, "balanced": 6, "maximum": 9}

        # Create temporary filenames
        local_temp_zip = os.path.join(
            tempfile.gettempdir(), f"remote_download_{int(time.time())}.zip"
        )
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
                with tempfile.NamedTemporaryFile(
                    suffix=".py", delete=False
                ) as script_file:
                    script_path = script_file.name
                    script_file.write(compression_script.encode("utf-8"))

                self.log("Uploading compression script to remote server")
                self.sftp.put(script_path, remote_script_path)
                # Make it executable
                self.sftp.chmod(remote_script_path, 0o755)
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
                            self.update_progress(
                                f"Compressing files: {compress_current}/{compress_total}",
                                progress,
                            )
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
                error_output = stderr.read().decode("utf-8")
                self.log(f"Error during remote compression: {error_output}")
                raise Exception(f"Remote compression failed with exit code {exit_code}")

            # Check if we need to stop before downloading
            if stop_check and stop_check():
                self.log("Download stopped before downloading archive")
                return total_files, transferred_files, error_count

            # Step 3: Download the compressed file
            self.log(
                f"Downloading compressed archive from {remote_temp_zip} to {local_temp_zip}"
            )

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
            with zipfile.ZipFile(local_temp_zip, "r") as zipf:
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
                        self.update_progress(
                            f"Extracting files: {i+1}/{len(infolist)}", progress
                        )

            # Clean up remote temporary files
            try:
                self.log("Cleaning up remote temporary files")
                self.sftp.remove(remote_temp_zip)
                self.sftp.remove(remote_script_path)
            except Exception as e:
                self.log(
                    f"Warning: Could not clean up remote temporary files: {str(e)}"
                )

        except Exception as e:
            self.log(f"Error during compressed download: {str(e)}")
            error_count += 1

        finally:
            # Clean up local temporary files
            try:
                if os.path.exists(local_temp_zip):
                    os.unlink(local_temp_zip)
                if "script_path" in locals() and os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception as e:
                self.log(f"Warning: Could not clean up local temporary files: {str(e)}")

        return total_files, transferred_files, error_count

    def sftp_walk(self, remote_dir):
        """Recursively walk through remote directory structure using SFTP.
        Similar to os.walk(), yields (root, dirs, files) for each directory.
        
        Args:
            remote_dir: Remote directory path to walk through
        """
        # Get the directory listing
        try:
            items = self.sftp.listdir_attr(remote_dir)
        except FileNotFoundError:
            self.log(f"Remote directory not found: {remote_dir}")
            return
        except Exception as e:
            self.log(f"Error listing remote directory {remote_dir}: {str(e)}")
            return

        # Separate files and directories
        files = []
        dirs = []
        
        for item in items:
            if stat.S_ISDIR(item.st_mode):
                # It's a directory
                dirs.append(item.filename)
            else:
                # It's a file
                files.append(item.filename)

        # First yield the current directory's info
        yield remote_dir, dirs, files

        # Then recursively walk through subdirectories
        for dir_name in dirs:
            # Construct the full path
            path = os.path.join(remote_dir, dir_name).replace("\\", "/")
            
            # Recursively walk through subdirectories
            for x in self.sftp_walk(path):
                yield x

    def _calculate_file_hash(self, file_path, chunk_size=8192):
        """Calculate MD5 hash of a local file"""
        try:
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for {file_path}: {str(e)}")
            return None

    def _calculate_remote_file_hash(self, remote_path, chunk_size=8192):
        """Calculate MD5 hash of a remote file"""
        try:
            md5_hash = hashlib.md5()
            with self.sftp.open(remote_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for remote file {remote_path}: {str(e)}")
            return None

    def _walk_remote_dir(self, source_dir, dest_dir, files_to_transfer, exclusions, total_files_counter):
        """Walk through remote directory and collect files to transfer
        
        Args:
            source_dir: Remote source directory
            dest_dir: Local destination directory
            files_to_transfer: List to populate with (source, dest) file tuples
            exclusions: List of folder exclusions
            total_files_counter: Integer to track total file count
        """
        try:
            # Normalize source directory path for consistent comparison
            source_dir = source_dir.replace("\\", "/")
            if not source_dir.endswith("/"):
                source_dir += "/"
                
            # Log the directory being scanned
            self.log(f"DEBUG: Scanning remote directory: {source_dir}")
            self.update_progress(status_message=f"Scanning: {source_dir}", current_directory=source_dir)

            # Use sftp_walk to traverse the remote directory structure
            for root, dirs, files in self.sftp_walk(source_dir):
                # Normalize the relative path of this directory
                rel_root = os.path.relpath(root, source_dir).replace("\\", "/")
                if rel_root == ".":
                    rel_root = ""
                
                # Apply exclusions before processing this directory
                if exclusions:
                    # Check if this directory should be entirely skipped
                    dir_rel_path = rel_root if rel_root else ""
                    skip_dir = False
                    
                    for exclusion in exclusions:
                        # Normalize exclusion path - ensure consistent slashes
                        exclusion = exclusion.replace("\\", "/")
                        
                        # Check if current directory matches or starts with the exclusion
                        if (dir_rel_path == exclusion or 
                            dir_rel_path.startswith(exclusion + "/") or 
                            root.replace("\\", "/").endswith("/" + exclusion) or
                            ("/" + dir_rel_path + "/").find("/" + exclusion + "/") >= 0):
                            self.log(f"DEBUG: Excluding directory: {root} (matches exclusion {exclusion})")
                            skip_dir = True
                            break
                    
                    if skip_dir:
                        # Skip this directory and its subdirectories
                        continue
                    
                    # Filter subdirectories to avoid recursing into excluded ones
                    dirs_to_remove = []
                    for i, d in enumerate(dirs):
                        subdir_path = os.path.join(rel_root, d).replace("\\", "/")
                        for exclusion in exclusions:
                            exclusion = exclusion.replace("\\", "/")
                            if (subdir_path == exclusion or 
                                subdir_path.startswith(exclusion + "/") or
                                d == exclusion or
                                ("/" + subdir_path + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Skipping excluded subdirectory: {subdir_path}")
                                dirs_to_remove.append(i)
                                break
                    
                    # Remove excluded directories in reverse order to maintain indices
                    for i in sorted(dirs_to_remove, reverse=True):
                        del dirs[i]
                
                # Process files in the current directory
                for file in files:
                    remote_path = os.path.join(root, file).replace("\\", "/")
                    relative_path = os.path.relpath(remote_path, source_dir).replace("\\", "/")
                    local_path = os.path.join(dest_dir, relative_path)
                    
                    # Check if file is in an excluded directory
                    if exclusions:
                        file_dir = os.path.dirname(relative_path).replace("\\", "/")
                        skip_file = False
                        for exclusion in exclusions:
                            exclusion = exclusion.replace("\\", "/")
                            if (file_dir == exclusion or 
                                file_dir.startswith(exclusion + "/") or
                                ("/" + file_dir + "/").find("/" + exclusion + "/") >= 0):
                                self.log(f"DEBUG: Skipping file in excluded directory: {relative_path}")
                                skip_file = True
                                break
                        if skip_file:
                            continue
                    
                    # Add file to transfer list
                    files_to_transfer.append((remote_path, local_path))
                    total_files_counter[0] = total_files_counter[0] + 1  # Update counter
            
            self.log(f"DEBUG: Found {total_files_counter[0]} files to transfer from remote directories")
            
        except Exception as e:
            self.log(f"Error walking remote directory {source_dir}: {str(e)}")

    def _ensure_remote_dir(self, remote_dir):
        """Ensure remote directory exists, creating it and parent directories if needed
        
        Args:
            remote_dir: Path to the remote directory
        """
        if not remote_dir:
            return
        
        # Normalize path
        remote_dir = remote_dir.replace("\\", "/")
        
        # Handle absolute paths on remote server
        if remote_dir.startswith("/"):
            path_to_check = "/"
            parts = remote_dir.strip("/").split("/")
        else:
            # Get current directory as starting point for relative paths
            try:
                path_to_check = self.sftp.getcwd() or ""
            except Exception:
                path_to_check = ""
            parts = remote_dir.split("/")
        
        # Remove empty parts
        parts = [p for p in parts if p]
        
        # Iteratively create directories
        for part in parts:
            if not part:
                continue
                
            if path_to_check:
                path_to_check = f"{path_to_check}/{part}"
            else:
                path_to_check = part
                
            try:
                # Check if directory exists
                self.sftp.stat(path_to_check)
            except FileNotFoundError:
                try:
                    # Create directory if it doesn't exist
                    self.log(f"DEBUG: Creating remote directory: {path_to_check}")
                    self.sftp.mkdir(path_to_check)
                except Exception as e:
                    self.log(f"Error creating remote directory {path_to_check}: {str(e)}")
                    raise
