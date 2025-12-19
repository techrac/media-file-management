import os
import traceback
import sys
import argparse
import re
from datetime import datetime
import hashlib
from collections import defaultdict

from timezonefinder import TimezoneFinder
from zoneinfo import ZoneInfo

def get_exiftool_executable():
    """
    Returns the path to the exiftool executable.
    Handles both development and packaged app scenarios.
    """
    import shutil
    
    # Check if we're running from a packaged app (cx_Freeze)
    if getattr(sys, 'frozen', False):
        # Running from a packaged app
        if sys.platform == 'darwin':  # macOS
            # In macOS app bundle, exiftool is in Contents/Resources/
            app_dir = os.path.dirname(sys.executable)
            # Go up from MacOS to Contents, then to Resources
            resources_dir = os.path.join(os.path.dirname(app_dir), 'Resources')
            exiftool_path = os.path.join(resources_dir, 'exiftool')
            
            if os.path.exists(exiftool_path) and os.access(exiftool_path, os.X_OK):
                return exiftool_path
        else:
            # For other platforms, exiftool should be in the same directory as the executable
            exiftool_path = os.path.join(os.path.dirname(sys.executable), 'exiftool')
        
            if os.path.exists(exiftool_path) and os.access(exiftool_path, os.X_OK):
                return exiftool_path
    
    # Fallback: try to find exiftool in PATH (development environment)
    exiftool_path = shutil.which('exiftool')
    if exiftool_path:
        return exiftool_path
    
    # If we get here, we couldn't find exiftool
    raise Exception("Could not find exiftool executable. Please ensure exiftool is installed and accessible.")

# Create a single TimezoneFinder instance for reuse to improve performance.
tf = TimezoneFinder()

def find_files_by_extension(directory_path: str, extensions: list[str]) -> list[str]:
    """
    Finds all files in a directory that match a given list of extensions.

    The search is case-insensitive.

    Args:
        directory_path: The absolute or relative path to the directory to search.
        extensions: A list of file extensions to find (e.g., ['.jpg', '.mov']).

    Returns:
        A list of full, absolute paths to the matching files.
    """
    if not os.path.isdir(directory_path):
        raise Exception(f"This is not a directory '{directory_path}'")

    # Ensure extensions are lowercase and start with a dot for consistent matching
    normalized_extensions = tuple(
        ext.lower() if ext.startswith('.') else f".{ext.lower()}"
        for ext in extensions
    )

    matching_files = []
    for filename in sorted(os.listdir(directory_path)):
        file_path = os.path.join(directory_path, filename)
        
        # Check if it's a file and if its extension matches
        if os.path.isfile(file_path) and filename.lower().endswith(normalized_extensions):
            matching_files.append(os.path.abspath(file_path))
            
    return matching_files

def get_local_time_from_utc(utc_dt: datetime, lat: float, lon: float) -> datetime:
    """
    Converts a naive UTC datetime to a naive local datetime based on GPS coordinates.
    This function correctly handles historical and future Daylight Saving Time.
    Args:
        utc_dt: A naive datetime object assumed to be in UTC.
        lat: Latitude.
        lon: Longitude.
    Returns:
        A naive datetime object representing the local time, or None if the
        timezone cannot be determined.
    """
    # Create a TimezoneFinder instance. It's efficient to reuse this object

    # 1. Find the timezone name (e.g., 'America/New_York') from the coordinates
    timezone_name = tf.timezone_at(lng=lon, lat=lat)
    if not timezone_name:
        raise Exception(f"Warning: Could not find timezone for lat={lat}, lon={lon}")

    # 2. Get the timezone object from the name
    local_timezone = ZoneInfo(timezone_name)
    
    # 3. Make the naive UTC datetime timezone-aware
    aware_utc_dt = utc_dt.replace(tzinfo=ZoneInfo("UTC"))
    
    # 4. Convert to the local timezone
    local_dt = aware_utc_dt.astimezone(local_timezone)
    
    # 5. Return as a naive datetime object (without timezone info)
    return local_dt.replace(tzinfo=None)    

def parse_date_time(date_time_str: str) -> datetime:
    if '+' in date_time_str:
        date_str = date_time_str.split('+')[0]
    elif '-' in date_time_str:
        date_str = date_time_str.split('-')[0]
    else:
        date_str = date_time_str
    return datetime.strptime(date_str, '%Y:%m:%d %H:%M:%S')

def extract_date_from_metadata(metadata, timezone: str | None = None) -> tuple[datetime, str, str]:
    
    file_name = os.path.basename(metadata['SourceFile'])

    quicktime_date = metadata.get('QuickTime:CreateDate') # UTC
    exif_date = metadata.get('EXIF:CreateDate') or metadata.get('EXIF:DateTimeOriginal') # local 

    lat_val = metadata.get('Composite:GPSLatitude')
    lon_val = metadata.get('Composite:GPSLongitude')
    lat = round(lat_val, 4) if lat_val is not None else None
    lon = round(lon_val, 4) if lon_val is not None else None

    brand = metadata.get('EXIF:Make') or metadata.get('QuickTime:Make')
    model = metadata.get('EXIF:Model') or metadata.get('QuickTime:Model')

    exif_date_offset = metadata.get('EXIF:OffsetTime')
    quicktime_creation_date = metadata.get('QuickTime:CreationDate')
    keys_creation_date = metadata.get('Keys:CreationDate')
    
    flag = None

    if exif_date:
        timestamp = parse_date_time(exif_date)
        flag = 'exif'
    elif quicktime_creation_date and ('+' in quicktime_creation_date or '-' in quicktime_creation_date):
        timestamp = parse_date_time(quicktime_creation_date)
        flag = 'quicktime'
    elif quicktime_date:
        raw_date = parse_date_time(quicktime_date)
        if lat is not None and lon is not None:
            timestamp = get_local_time_from_utc(raw_date, lat, lon)
            flag = 'converted_gps'
        elif timezone:
            try:
                target_zone = ZoneInfo(timezone)
                aware_utc_dt = raw_date.replace(tzinfo=ZoneInfo("UTC"))
                local_dt = aware_utc_dt.astimezone(target_zone)
                timestamp = local_dt.replace(tzinfo=None)
                flag = 'converted_tz'
            except Exception as e:
                raise Exception(f"Invalid timezone '{timezone}': {e}") from e
        else:
            raise Exception(f"No timezone information found in metadata. Please explicitly specify the timezone. QuickTime:CreateDate appears to be in UTC: {raw_date}")
    else:
        raise Exception(f"Unable to extract a timestamp from metadata")
    
    debug_data = f"{(quicktime_date or 'N/A'):<20} {(exif_date or 'N/A'):<20} {(lat or 'N/A'):<10} {(lon or 'N/A'):<10} {(brand or 'N/A'):<15} {(model or 'N/A'):<25} {(exif_date_offset or 'N/A'):<10} {(quicktime_creation_date or 'N/A'):<25} {(keys_creation_date or 'N/A'):<20}"

    return timestamp, debug_data, flag

def calculate_checksum(file_path: str, block_size: int = 65536) -> str:
    """Calculates the SHA256 checksum of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except IOError:
        print(f"Warning: Could not read file {file_path}")
        return ""

def find_duplicate_files(directory_path: str) -> dict[str, list[str]]:
    """
    Finds duplicate files in a directory and its subdirectories based on SHA256 checksum.

    Args:
        directory_path: The absolute or relative path to the directory to search.

    Returns:
        A dictionary where keys are checksums and values are lists of paths
        to files with that checksum. Only includes checksums with more than one file.
    """
    if not os.path.isdir(directory_path):
        raise ValueError(f"'{directory_path}' is not a valid directory.")

    checksums = defaultdict(list)
    print("Scanning files and calculating checksums...")
    # Get total number of files for progress indication
    file_list = [os.path.join(dirpath, filename) for dirpath, _, filenames in os.walk(directory_path) for filename in filenames]
    total_files = len(file_list)

    for i, file_path in enumerate(file_list):
        print(f"Processing file {i+1}/{total_files}: {os.path.basename(file_path):<100}", end='\r')
        if os.path.isfile(file_path):
            checksum = calculate_checksum(file_path)
            if checksum:  # Ignore files that couldn't be read
                checksums[checksum].append(file_path)
    print("\nScan complete. Finding duplicates...")
    # Filter to find files with more than one path for a given checksum
    duplicates = {checksum: paths for checksum, paths in checksums.items() if len(paths) > 1}
    return duplicates

def rename_media(folder_path: str, timezone: str | None = None, dry_run: bool = False, debug: bool = False, force_overwrite: bool = False):
    try:
        photos_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.heic')
        videos_extensions = ('.mp4', '.avi', '.mov')

        count_ok = 0
        count_renamed = 0
        errors = []
        count = 0
        logs = []

        if not os.path.isdir(folder_path):
            raise Exception(f"Error: '{folder_path}' is not a folder.")

        files = find_files_by_extension(folder_path, photos_extensions + videos_extensions)
        count_total = len(files)

        import exiftool
        
        # Use our custom exiftool path resolution for reliable cross-platform support
        try:
            exiftool_path = get_exiftool_executable()
            with exiftool.ExifToolHelper(executable=exiftool_path) as et:
                metadata_list = et.get_metadata(files)
        except Exception as e:
            raise Exception(f"ExifTool operation failed: {e}")

        if debug:
            print(f"[{'count':<5}/{'total':<5}] -- {'flag':<15} {'file_name':<40} {'quicktime_date':<20} {'exif_date':<20} {'lat':<10} {'lon':<10} {'brand':<15} {'model':<25} {'exif_offst':<10} {'qt_creation_date':<25} {'k_creation_date':<20}")
            print(f"[{'===':<5}/{'===':<5}] -- {'====':<15} {'=========':<40} {'==============':<20} {'=========':<20} {'===':<10} {'===':<10} {'=====':<15} {'=====':<25} {'==========':<10} {'================':<25} {'===============':<20}")

        for metadata in metadata_list:
            count += 1
            file_path = metadata['SourceFile']
            file_name = os.path.basename(file_path)
            dt_object = None
            debug_data = None
            flag = None

            try:
                dt_object, debug_data, flag = extract_date_from_metadata(metadata= metadata, timezone=timezone)
                count_ok += 1
                if debug:
                    print(f"[{count:<5}/{count_total:<5}] OK {flag:<15} {file_name:<40} {debug_data} => {dt_object}")
            except Exception as ex:
                if debug:
                    print(f"[{count:<5}/{count_total:<5}] KO {'---':<15} {file_name:<40} => {ex}")
                errors.append(file_name)
                continue

            # Format the timestamp for the new filename
            timestamp_prefix = dt_object.strftime('%Y%m%d_%H%M%S')
            date_prefix = dt_object.strftime('%Y%m%d')
            time_prefix = dt_object.strftime('%H%M%S')

            # Get original name and lowercase extension
            original_name, extension = os.path.splitext(file_name)
            lower_extension = extension.lower()

            # Handle force_overwrite: detect and remove existing timestamp prefixes
            if force_overwrite:
                # Pattern to match existing timestamp prefixes: YYYYMMDD_HHMMSS or YYYYMMDD_HHMMSS_*
                existing_timestamp_pattern = r'^(\d{8}_\d{6})(?:_[A-Z]+)?(?:-|_)(.*)$'
                match = re.match(existing_timestamp_pattern, original_name)
                if match:
                    timestamp_str = match.group(1)  # YYYYMMDD_HHMMSS
                    try:
                        # Validate that this is actually a valid date
                        year = int(timestamp_str[:4])
                        month = int(timestamp_str[4:6])
                        day = int(timestamp_str[6:8])
                        hour = int(timestamp_str[9:11])
                        minute = int(timestamp_str[11:13])
                        second = int(timestamp_str[13:15])
                        
                        # Basic validation
                        if (1 <= month <= 12 and 1 <= day <= 31 and 
                            0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59 and
                            1900 <= year <= 2100):  # Reasonable year range
                            
                            # Extract the original name part after removing timestamp prefix
                            original_name = match.group(2)
                            if debug:
                                print(f"[FORCE OVERWRITE] Detected valid timestamp in '{file_name}', original name: '{original_name}'")
                        else:
                            if debug:
                                print(f"[FORCE OVERWRITE] Invalid date in timestamp '{timestamp_str}' in '{file_name}'")
                    except (ValueError, IndexError):
                        if debug:
                            print(f"[FORCE OVERWRITE] Invalid timestamp format '{timestamp_str}' in '{file_name}'")
                else:
                    if debug:
                        print(f"[FORCE OVERWRITE] No existing timestamp prefix found in '{file_name}'")

            # remove timestamps duplicates
            original_name_cleaned = original_name.replace(timestamp_prefix, '').replace(date_prefix, '').replace(time_prefix, '').replace('(', '').replace(')', '')

            # Normalize separators
            original_name_cleaned = re.sub(r'[ ._-]+', '_', original_name_cleaned).strip('_')

            # Construct new filename with timestamp prefix and original name suffix
            new_filename_base = f"{timestamp_prefix}-{original_name_cleaned}"
            new_filename_base = new_filename_base.strip('_').strip('-').strip()

            new_filename = f"{new_filename_base}{lower_extension}"
            new_file_path = os.path.join(folder_path, new_filename)

            # Skip if the new filename is the same as the current filename
            if new_filename == file_name:
                if debug:
                    print(f"[SKIP] Filename unchanged: {file_name}")
                continue

            # check for name collisions
            if os.path.exists(new_file_path):
                raise Exception(f"{new_filename} already exists")

            count_renamed += 1

            if dry_run:
                print(f"[RENAMING] {count:>{5}}   {file_name:<{60}} {new_filename}")    
            else:
                os.rename(file_path, new_file_path)
                logs.append(f"Renamed ; '{file_name}' ; '{new_filename}'")

        print(f"==== counts: total:{count_total}    parsed:{len(metadata_list)}    ok:{count_ok}    renamed:{count_renamed}    error:{len(errors)}")
        for e in errors:
            print(f"error: {e}")

    finally:
        if len(logs) > 0:
            log_file = os.path.join(folder_path, f"_renaming_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(log_file, 'w', encoding='utf-8') as log_handle:
                log_handle.writelines(f"{log}\n" for log in logs)

def process_duplicate_files(folder_path: str, dry_run: bool = False, debug: bool = False):
    print(f"Scanning for duplicate files in '{folder_path}'...")
    duplicates = find_duplicate_files(folder_path)
    
    if not duplicates:
        print("No duplicate files found.")
        return

    print(f"\nFound {len(duplicates)} set(s) of duplicate files:")
    total_deleted = 0
    for checksum, paths in duplicates.items():
        print(f"\nChecksum: {checksum}")
        
        # Sort by path length, then alphabetically as a tie-breaker
        sorted_paths = sorted(paths, key=lambda p: (len(p), p))
        
        file_to_keep = sorted_paths[0]
        files_to_delete = sorted_paths[1:]
        
        print(f"  - Keeping:   {file_to_keep}")
        
        for path in files_to_delete:
            print(f"  - Duplicate: {path}")
            if dry_run:
                print(f"    -> [DRY RUN] Would delete this file.")
            else:
                try:
                    os.remove(path)
                    print(f"    -> DELETED.")
                    total_deleted += 1
                except OSError as e:
                    print(f"    -> ERROR: Could not delete file: {e}")
    
    if dry_run:
        print(f"\nDry run complete. Total files that would have been deleted: {total_deleted}")
    else:
        print(f"\nDeletion complete. Total files deleted: {total_deleted}")

def flatten_directory(folder_path: str, dry_run: bool = False):
    """
    Moves all files from all subdirectories into the root folder and removes empty subdirectories.
    Handles filename collisions by appending a number.

    Args:
        folder_path: The path to the root folder.
        dry_run: If True, only print what would be done.
    """
    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' is not a valid directory.")
        return

    print(f"Flattening directory '{folder_path}'...")
    if dry_run:
        print("--- DRY RUN MODE ---")

    moved_count = 0
    # Step 1: Walk through directories and move files
    for dirpath, _, filenames in os.walk(folder_path):
        # Skip the root directory itself
        if os.path.samefile(dirpath, folder_path):
            continue

        for filename in filenames:
            source_path = os.path.join(dirpath, filename)
            dest_path = os.path.join(folder_path, filename)

            # Step 2: Handle filename collisions
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                # Find a new name by appending _1, _2, etc.
                while True:
                    new_filename = f"{base}_{counter}{ext}"
                    new_dest_path = os.path.join(folder_path, new_filename)
                    if not os.path.exists(new_dest_path):
                        dest_path = new_dest_path
                        break
                    counter += 1
                print(f"  - Collision: '{filename}' exists. Renaming to '{os.path.basename(dest_path)}'")

            # Step 3: Move the file
            action_msg = f"Moving '{os.path.relpath(source_path, folder_path)}' to root"
            if dry_run:
                print(f"[DRY RUN] {action_msg}")
            else:
                try:
                    os.rename(source_path, dest_path)
                    print(action_msg)
                except OSError as e:
                    print(f"  -> ERROR: Could not move file: {e}")
                    continue # Skip to next file if move fails
            moved_count += 1

    print(f"\nFinished moving files. Total files that would be/were moved: {moved_count}")

    # Step 4: Clean up empty subdirectories
    print("Cleaning up empty subdirectories...")
    # Walk bottom-up to safely delete empty subdirs
    for dirpath, _, _ in os.walk(folder_path, topdown=False):
        # Don't try to delete the root folder or non-existent paths
        if os.path.samefile(dirpath, folder_path) or not os.path.isdir(dirpath):
            continue

        # Check if directory is empty and remove it
        if not os.listdir(dirpath):
            action_msg = f"Removing empty directory: '{os.path.relpath(dirpath, folder_path)}'"
            if dry_run:
                print(f"[DRY RUN] {action_msg}")
            else:
                try:
                    os.rmdir(dirpath)
                    print(action_msg)
                except OSError as e:
                    print(f"  -> ERROR: Could not remove directory: {e}")

    print("Flattening complete.")

# ============================================================================
# SSH-Based Remote Cleanup Functions
# ============================================================================

def connect_ssh(host: str, username: str, key_file: str, port: int = 22):
    """
    Establishes SSH connection using paramiko. Uses key-based authentication only.
    
    Args:
        host: QNAP hostname or IP address
        username: SSH username
        key_file: Path to SSH private key file
        port: SSH port (default: 22)
    
    Returns:
        SSHClient instance
    """
    import paramiko
    
    if not os.path.exists(key_file):
        raise Exception(f"SSH key file not found: {key_file}")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(hostname=host, username=username, key_filename=key_file, port=port, timeout=30)
        return ssh
    except Exception as e:
        raise Exception(f"Failed to connect via SSH: {e}") from e

def execute_ssh_command(ssh_client, command: str):
    """
    Executes a remote command and returns stdout, stderr, and exit code.
    
    Args:
        ssh_client: SSHClient instance
        command: Command to execute
    
    Returns:
        tuple: (stdout, stderr, exit_code)
    """
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=300)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode('utf-8', errors='replace')
        stderr_text = stderr.read().decode('utf-8', errors='replace')
        return stdout_text, stderr_text, exit_code
    except Exception as e:
        raise Exception(f"Failed to execute SSH command: {e}") from e

def disconnect_ssh(ssh_client):
    """Closes SSH connection safely."""
    try:
        ssh_client.close()
    except Exception:
        pass

def scan_permission_issues(ssh_client, share_path: str, username: str):
    """
    Scans for permission issues: wrong ownership and executable image files.
    
    Args:
        ssh_client: SSHClient instance
        share_path: Path to the share root
        username: Username of the share owner
    
    Returns:
        dict with keys: 'wrong_owner_files', 'wrong_owner_dirs', 'executable_images'
    """
    results = {
        'wrong_owner_files': [],
        'wrong_owner_dirs': [],
        'executable_images': []
    }
    
    # Find files with wrong ownership
    cmd = f"find '{share_path}' -type f -not -user {username} 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['wrong_owner_files'] = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    
    # Find directories with wrong ownership
    cmd = f"find '{share_path}' -type d -mindepth 1 -not -user {username} 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['wrong_owner_dirs'] = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    
    # Find executable image files
    cmd = f"find '{share_path}' -type f \\( -perm -u=x -o -perm -g=x -o -perm -o=x \\) \\( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.bmp' -o -iname '*.tiff' \\) 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['executable_images'] = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    
    return results

def scan_empty_folders_remote(ssh_client, share_path: str, exclude_patterns: list):
    """
    Scans for empty directories, excluding specified patterns.
    
    Args:
        ssh_client: SSHClient instance
        share_path: Path to the share root
        exclude_patterns: List of folder names to exclude (e.g., ['.fcpbundle'])
    
    Returns:
        List of empty folder paths (deepest first)
    """
    # Build exclude pattern for find command
    exclude_args = ' '.join([f"-not -name '{pattern}'" for pattern in exclude_patterns])
    
    # Find empty directories
    cmd = f"find '{share_path}' -type d -mindepth 1 {exclude_args} -exec sh -c 'if [ -z \"$(ls -A \"$1\" 2>/dev/null)\" ]; then echo \"$1\"; fi' sh {{}} \\; 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    
    empty_folders = []
    if stdout.strip():
        empty_folders = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
    
    # Sort by path depth (deepest first) for safe deletion
    empty_folders.sort(key=lambda x: x.count('/'), reverse=True)
    
    return empty_folders

def scan_legacy_files_remote(ssh_client, share_path: str):
    """
    Scans for legacy files and directories to delete.
    
    Args:
        ssh_client: SSHClient instance
        share_path: Path to the share root
    
    Returns:
        dict with keys: 'files', 'directories', 'resource_forks'
    """
    results = {
        'files': [],
        'directories': [],
        'resource_forks': []
    }
    
    # Windows cache files
    cache_files = ['Thumbs.db', 'ehthumbs.db', 'ehthumbs_vista.db', 'Desktop.ini', 'IconCache.db']
    for cache_file in cache_files:
        cmd = f"find '{share_path}' -type f -name '{cache_file}' 2>/dev/null"
        stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
        if stdout.strip():
            results['files'].extend([line.strip() for line in stdout.strip().split('\n') if line.strip()])
    
    # .@__thumb directories
    cmd = f"find '{share_path}' -type d -name '.@__thumb' 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['directories'].extend([line.strip() for line in stdout.strip().split('\n') if line.strip()])
    
    # .streams folder at root only
    streams_path = share_path.rstrip('/') + '/.streams'
    cmd = f"if [ -d '{streams_path}' ]; then echo '{streams_path}'; fi 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['directories'].append(stdout.strip())
    
    # ._* resource fork files (only if matching non-prefixed file exists)
    # Use a bash script to check both conditions in one pass
    cmd = f"find '{share_path}' -type f -name '._*' 2>/dev/null | while read rf_file; do dir_path=$(dirname \"$rf_file\"); base_name=$(basename \"$rf_file\"); matching_name=\"${{base_name#._}}\"; if [ \"$matching_name\" != \"$base_name\" ]; then matching_path=\"$dir_path/$matching_name\"; if [ -f \"$matching_path\" ]; then echo \"$rf_file\"; fi; fi; done"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    if stdout.strip():
        results['resource_forks'].extend([line.strip() for line in stdout.strip().split('\n') if line.strip()])
    
    return results

def scan_problematic_filenames_remote(ssh_client, share_path: str, problem_chars: list, char_replacements: list):
    """
    Scans for files/directories containing problematic characters.
    
    Args:
        ssh_client: SSHClient instance
        share_path: Path to the share root
        problem_chars: List of problematic characters (e.g., [':', '~'])
        char_replacements: List of replacement characters (e.g., ['-', '_'])
    
    Returns:
        List of tuples: (original_path, sanitized_path)
    """
    if len(problem_chars) != len(char_replacements):
        raise ValueError("problem_chars and char_replacements must have the same length")
    
    # Build find pattern to match files/dirs with problematic characters
    char_pattern = ' '.join([f"-o -name '*{char}*'" for char in problem_chars])
    char_pattern = char_pattern[4:]  # Remove leading " -o "
    
    cmd = f"find '{share_path}' \\( -type f -o -type d \\) \\( {char_pattern} \\) 2>/dev/null"
    stdout, stderr, exit_code = execute_ssh_command(ssh_client, cmd)
    
    rename_list = []
    if stdout.strip():
        paths = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        for path in paths:
            sanitized = path
            for prob_char, repl_char in zip(problem_chars, char_replacements):
                sanitized = sanitized.replace(prob_char, repl_char)
            if sanitized != path:
                rename_list.append((path, sanitized))
    
    return rename_list

def escape_shell_path(path: str) -> str:
    """Escapes a path for safe use in shell commands."""
    # Replace single quotes with '\''
    escaped = path.replace("'", "'\\''")
    return f"'{escaped}'"

def generate_categorized_cleanup_scripts(
    share_path: str,
    username: str,
    permission_issues: dict = None,
    empty_folders: list = None,
    legacy_files: dict = None,
    problematic_filenames: list = None,
    exclude_patterns: list = None,
    output_dir: str = None
):
    """
    Generates categorized bash script files for cleanup operations.
    
    Args:
        share_path: Path to the share root
        username: Username of the share owner
        permission_issues: Dict from scan_permission_issues
        empty_folders: List from scan_empty_folders_remote
        legacy_files: Dict from scan_legacy_files_remote
        problematic_filenames: List of tuples from scan_problematic_filenames_remote
        exclude_patterns: List of folder names to exclude
        output_dir: Directory to write scripts (default: timestamped directory in user's home/Documents)
    """
    if output_dir is None:
        # Use Documents folder or home directory as default location (writable by user)
        home_dir = os.path.expanduser("~")
        documents_dir = os.path.join(home_dir, "Documents")
        if os.path.exists(documents_dir) and os.access(documents_dir, os.W_OK):
            base_dir = documents_dir
        else:
            base_dir = home_dir
        output_dir = os.path.join(base_dir, f"qnap_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    else:
        # If user provided a relative path, make it absolute from home directory
        if not os.path.isabs(output_dir):
            home_dir = os.path.expanduser("~")
            output_dir = os.path.join(home_dir, output_dir)
    
    os.makedirs(output_dir, exist_ok=True)
    
    exclude_patterns = exclude_patterns or ['.fcpbundle']
    
    scripts_generated = []
    
    # 1. permissions_to_fix.sh
    if permission_issues:
        script_path = os.path.join(output_dir, 'permissions_to_fix.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Generated cleanup script for QNAP SSH terminal\n")
            f.write(f"# Target path: {share_path}\n")
            f.write(f"# Share owner: {username}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("set -e  # Exit on error\n\n")
            f.write("echo \"=== Fixing File Ownership ===\"\n")
            f.write(f"sudo find {escape_shell_path(share_path)} -not -user {username} -exec chown {username}:everyone {{}} \\;\n")
            f.write(f"sudo find {escape_shell_path(share_path)} -not -group everyone -exec chown {username}:everyone {{}} \\;\n\n")
            f.write("echo \"=== Fixing Directory Permissions ===\"\n")
            f.write(f"find {escape_shell_path(share_path)} -mindepth 1 -type d -exec chmod u+x {{}} \\;\n\n")
            f.write("echo \"=== Removing Execute Permissions from Image Files ===\"\n")
            f.write(f"sudo find {escape_shell_path(share_path)} -type f \\( -perm -u=x -o -perm -g=x -o -perm -o=x \\) \\\n")
            f.write("  \\( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.bmp' -o -iname '*.tiff' \\) \\\n")
            f.write("  -exec chmod -x {{}} \\;\n\n")
            f.write("echo \"=== Permission fixes complete ===\"\n")
        os.chmod(script_path, 0o755)
        scripts_generated.append(script_path)
    
    # 2. files_to_delete.sh
    if legacy_files and (legacy_files.get('files') or legacy_files.get('directories') or legacy_files.get('resource_forks')):
        script_path = os.path.join(output_dir, 'files_to_delete.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Generated cleanup script for QNAP SSH terminal\n")
            f.write(f"# Target path: {share_path}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("set -e  # Exit on error\n\n")
            
            if legacy_files.get('files'):
                f.write("echo \"=== Listing Windows cache files to delete ===\"\n")
                for file_path in legacy_files['files']:
                    f.write(f"# {file_path}\n")
                f.write("\necho \"=== Deleting Windows cache files ===\"\n")
                for file_path in legacy_files['files']:
                    f.write(f"sudo rm -f {escape_shell_path(file_path)}\n")
                f.write("\n")
            
            if legacy_files.get('directories'):
                f.write("echo \"=== Listing directories to delete ===\"\n")
                for dir_path in legacy_files['directories']:
                    f.write(f"# {dir_path}\n")
                f.write("\necho \"=== Deleting directories ===\"\n")
                for dir_path in legacy_files['directories']:
                    f.write(f"sudo rm -rf {escape_shell_path(dir_path)}\n")
                f.write("\n")
            
            if legacy_files.get('resource_forks'):
                f.write("echo \"=== Listing macOS resource fork files to delete ===\"\n")
                for file_path in legacy_files['resource_forks']:
                    f.write(f"# {file_path}\n")
                f.write("\necho \"=== Deleting macOS resource fork files ===\"\n")
                for file_path in legacy_files['resource_forks']:
                    f.write(f"sudo rm -f {escape_shell_path(file_path)}\n")
                f.write("\n")
            
            f.write("echo \"=== Legacy files deletion complete ===\"\n")
        os.chmod(script_path, 0o755)
        scripts_generated.append(script_path)
    
    # 3. folders_to_delete.sh
    if empty_folders:
        script_path = os.path.join(output_dir, 'folders_to_delete.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Generated cleanup script for QNAP SSH terminal\n")
            f.write(f"# Target path: {share_path}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("set -e  # Exit on error\n\n")
            f.write("echo \"=== Listing empty folders ===\"\n")
            exclude_args = ' '.join([f"-not -name '{pattern}'" for pattern in exclude_patterns])
            f.write(f"find {escape_shell_path(share_path)} -type d -mindepth 1 {exclude_args} -exec sh -c 'if [ -z \"$(ls -A \"$1\" 2>/dev/null)\" ]; then echo \"$1\"; fi' sh {{}} \\;\n\n")
            f.write("echo \"=== Deleting empty folders (multiple passes) ===\"\n")
            f.write("MAX_PASSES=10\n")
            f.write("for i in $(seq 1 $MAX_PASSES); do\n")
            exclude_args_rmdir = ' '.join([f"-not -name '{pattern}'" for pattern in exclude_patterns])
            f.write(f"  COUNT=$(find {escape_shell_path(share_path)} -type d -mindepth 1 {exclude_args_rmdir} -exec rmdir {{}} \\; 2>/dev/null | wc -l || echo 0)\n")
            f.write("  if [ $COUNT -eq 0 ]; then\n")
            f.write("    echo \"No more empty folders found after pass $i\"\n")
            f.write("    break\n")
            f.write("  fi\n")
            f.write("  echo \"Pass $i: Removed empty folders\"\n")
            f.write("done\n\n")
            f.write("echo \"=== Empty folder cleanup complete ===\"\n")
        os.chmod(script_path, 0o755)
        scripts_generated.append(script_path)
    
    # 4. files_to_rename.sh
    if problematic_filenames:
        script_path = os.path.join(output_dir, 'files_to_rename.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Generated cleanup script for QNAP SSH terminal\n")
            f.write(f"# Target path: {share_path}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("set -e  # Exit on error\n\n")
            f.write("echo \"=== Listing files/directories to rename ===\"\n")
            for orig_path, new_path in problematic_filenames:
                f.write(f"# {orig_path} -> {new_path}\n")
            f.write("\necho \"=== Renaming files/directories ===\"\n")
            for orig_path, new_path in problematic_filenames:
                f.write(f"sudo mv {escape_shell_path(orig_path)} {escape_shell_path(new_path)}\n")
            f.write("\necho \"=== Filename sanitization complete ===\"\n")
        os.chmod(script_path, 0o755)
        scripts_generated.append(script_path)
    
    # 5. run_all.sh - Master script
    if scripts_generated:
        script_path = os.path.join(output_dir, 'run_all.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write(f"# Master cleanup script for QNAP SSH terminal\n")
            f.write(f"# Target path: {share_path}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("set -e  # Exit on error\n\n")
            f.write("SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n\n")
            f.write("echo \"=== Starting QNAP Cleanup Scripts ===\"\n\n")
            
            # Execute scripts in order
            if permission_issues and os.path.exists(os.path.join(output_dir, 'permissions_to_fix.sh')):
                f.write("echo \"\\n[1/4] Running permission fixes...\"\n")
                f.write("bash \"$SCRIPT_DIR/permissions_to_fix.sh\"\n\n")
            
            if problematic_filenames and os.path.exists(os.path.join(output_dir, 'files_to_rename.sh')):
                f.write("echo \"\\n[2/4] Running filename sanitization...\"\n")
                f.write("bash \"$SCRIPT_DIR/files_to_rename.sh\"\n\n")
            
            if legacy_files and os.path.exists(os.path.join(output_dir, 'files_to_delete.sh')):
                f.write("echo \"\\n[3/4] Deleting legacy files...\"\n")
                f.write("bash \"$SCRIPT_DIR/files_to_delete.sh\"\n\n")
            
            if empty_folders and os.path.exists(os.path.join(output_dir, 'folders_to_delete.sh')):
                f.write("echo \"\\n[4/4] Deleting empty folders...\"\n")
                f.write("bash \"$SCRIPT_DIR/folders_to_delete.sh\"\n\n")
            
            f.write("echo \"\\n=== All cleanup operations complete ===\"\n")
        os.chmod(script_path, 0o755)
        scripts_generated.append(script_path)
    
    return output_dir, scripts_generated

def main():
    try:
        parser = argparse.ArgumentParser(
            description="Tool to organize media files (local mode) or generate cleanup scripts for QNAP (remote mode).",
            epilog="Local mode example: python main.py /path/to/photos --rename --debug\n"
                   "Remote mode example: python main.py --remote-mode --ssh-host qnap.local --ssh-user admin --ssh-key ~/.ssh/qnap_key --share-path /share/Jinhwa/ --share-owner jinhwa --cleanup-all"
        )
        
        # Mode selection
        parser.add_argument("--remote-mode", "--ssh-mode", action="store_true", 
                          help="Enable remote SSH mode (script generation only). If not specified, uses local mode.")
        
        # Local mode arguments
        parser.add_argument("folder_path", nargs='?', help="The path to the folder containing the media files (local mode only).")
        parser.add_argument("--debug", action="store_true", help="More verbose.")
        parser.add_argument("--dry-run", action="store_true", help="No file modification / deletion is done (local mode only).")
        parser.add_argument("--rename", action="store_true", help="Rename media files using their metadata timestamp (local mode only).")
        parser.add_argument("--delete-dups", action="store_true", help="Find duplicate files in the folder based on checksum (local mode only).")
        parser.add_argument("--flatten", action="store_true", help="Move all files from subdirectories to the root folder and remove empty subdirectories (local mode only).")
        parser.add_argument("--timezone", help="Specify a timezone (e.g., 'Europe/Paris') to use for UTC conversion when GPS data is missing (local mode only).")
        parser.add_argument("--force-overwrite", action="store_true", help="Force overwrite existing timestamp prefixes in filenames (local mode only).")
        
        # Remote mode arguments
        parser.add_argument("--ssh-host", help="QNAP hostname or IP address (remote mode required).")
        parser.add_argument("--ssh-user", help="SSH username (remote mode required).")
        parser.add_argument("--ssh-key", help="Path to SSH private key file (remote mode required).")
        parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22).")
        parser.add_argument("--share-path", help="Path to the share root on QNAP (e.g., /share/Jinhwa/) (remote mode required).")
        parser.add_argument("--share-owner", help="Username of the share owner (e.g., jinhwa) (remote mode required).")
        parser.add_argument("--cleanup-all", action="store_true", help="Enable all cleanup scans (permissions, empty folders, legacy files, filename fixes).")
        parser.add_argument("--cleanup-permissions", action="store_true", help="Enable permission fix scanning.")
        parser.add_argument("--cleanup-empty-folders", action="store_true", help="Enable empty folder cleanup scan.")
        parser.add_argument("--cleanup-legacy-files", action="store_true", help="Enable legacy file cleanup scan (includes Windows cache files, .streams, ._* resource fork files).")
        parser.add_argument("--cleanup-filenames", action="store_true", help="Enable filename character replacement scan.")
        parser.add_argument("--problem-chars", default=": ~", help="Comma-separated list of problematic characters to replace (default: ': ~').")
        parser.add_argument("--char-replacements", default="- _", help="Comma-separated list of replacement characters (default: '- _' - must match order of problem-chars).")
        parser.add_argument("--exclude-folder", default=".fcpbundle", help="Comma-separated list of folder names to exclude from empty folder cleanup (default: '.fcpbundle').")
        parser.add_argument("--output-dir", help="Directory for generated scripts (default: qnap_cleanup_YYYYMMDD_HHMMSS/).")
        
        args = parser.parse_args()

        # Route to appropriate mode
        if args.remote_mode:
            # Remote SSH mode
            if not args.ssh_host or not args.ssh_user or not args.ssh_key or not args.share_path or not args.share_owner:
                parser.error("Remote mode requires: --ssh-host, --ssh-user, --ssh-key, --share-path, and --share-owner")
            
            # Determine which cleanup operations to perform
            do_permissions = args.cleanup_all or args.cleanup_permissions
            do_empty_folders = args.cleanup_all or args.cleanup_empty_folders
            do_legacy_files = args.cleanup_all or args.cleanup_legacy_files
            do_filenames = args.cleanup_all or args.cleanup_filenames
            
            if not (do_permissions or do_empty_folders or do_legacy_files or do_filenames):
                parser.error("Remote mode requires at least one cleanup operation (use --cleanup-all or specific --cleanup-* flags)")
            
            # Parse problem chars and replacements
            problem_chars = [c.strip() for c in args.problem_chars.split(',')]
            char_replacements = [c.strip() for c in args.char_replacements.split(',')]
            if len(problem_chars) != len(char_replacements):
                parser.error("--problem-chars and --char-replacements must have the same number of items")
            
            exclude_patterns = [p.strip() for p in args.exclude_folder.split(',')]
            
            print(f"Connecting to {args.ssh_host}...")
            ssh_client = connect_ssh(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_port)
            print("Connected successfully.\n")
            
            try:
                permission_issues = None
                empty_folders = None
                legacy_files = None
                problematic_filenames = None
                
                if do_permissions:
                    print("Scanning for permission issues...")
                    permission_issues = scan_permission_issues(ssh_client, args.share_path, args.share_owner)
                    print(f"Found {len(permission_issues['wrong_owner_files'])} files and {len(permission_issues['wrong_owner_dirs'])} directories with wrong ownership.")
                    print(f"Found {len(permission_issues['executable_images'])} executable image files.\n")
                
                if do_empty_folders:
                    print("Scanning for empty folders...")
                    empty_folders = scan_empty_folders_remote(ssh_client, args.share_path, exclude_patterns)
                    print(f"Found {len(empty_folders)} empty folders.\n")
                
                if do_legacy_files:
                    print("Scanning for legacy files...")
                    legacy_files = scan_legacy_files_remote(ssh_client, args.share_path)
                    total_legacy = len(legacy_files.get('files', [])) + len(legacy_files.get('directories', [])) + len(legacy_files.get('resource_forks', []))
                    print(f"Found {total_legacy} legacy items to delete ({len(legacy_files.get('files', []))} files, {len(legacy_files.get('directories', []))} directories, {len(legacy_files.get('resource_forks', []))} resource forks).\n")
                
                if do_filenames:
                    print("Scanning for problematic filenames...")
                    problematic_filenames = scan_problematic_filenames_remote(ssh_client, args.share_path, problem_chars, char_replacements)
                    print(f"Found {len(problematic_filenames)} files/directories with problematic characters.\n")
                
                print("Generating cleanup scripts...")
                output_dir, scripts = generate_categorized_cleanup_scripts(
                    share_path=args.share_path,
                    username=args.share_owner,
                    permission_issues=permission_issues,
                    empty_folders=empty_folders,
                    legacy_files=legacy_files,
                    problematic_filenames=problematic_filenames,
                    exclude_patterns=exclude_patterns,
                    output_dir=args.output_dir
                )
                
                print(f"\n=== Scripts generated successfully ===")
                print(f"Output directory: {os.path.abspath(output_dir)}")
                print(f"Scripts generated: {len(scripts)}")
                for script in scripts:
                    print(f"  - {os.path.basename(script)}")
                print(f"\nReview the scripts and run them on your QNAP SSH terminal.")
                print(f"To run all scripts: bash {os.path.join(output_dir, 'run_all.sh')}")
                
            finally:
                disconnect_ssh(ssh_client)
        else:
            # Local mode
            if not args.folder_path:
                parser.error("Local mode requires folder_path argument")
            
            if args.flatten:
                flatten_directory(folder_path=args.folder_path, dry_run=args.dry_run)

            if args.delete_dups:
                process_duplicate_files(folder_path= args.folder_path, dry_run=args.dry_run, debug=args.debug)
                
            if args.rename:
                rename_media(folder_path= args.folder_path, timezone=args.timezone, dry_run=args.dry_run, debug=args.debug, force_overwrite=args.force_overwrite)

    except Exception as ex:
         print('=== FATAL ERROR')
         print(traceback.format_exc())

if __name__ == "__main__":
    main()