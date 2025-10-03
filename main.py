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
            timestamp = raw_date
            flag = 'assumed_local'
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

def rename_media(folder_path: str, timezone: str | None = None, dry_run: bool = False, debug: bool = False):
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

            if flag == 'assumed_local':
                timestamp_prefix += '_UTZ' # this is to show that the timestamp is in an unknown timezone

            # Get original name and lowercase extension
            original_name, extension = os.path.splitext(file_name)
            lower_extension = extension.lower()

            # remove timestamps duplicates
            original_name_cleaned = original_name.replace(timestamp_prefix, '').replace(date_prefix, '').replace(time_prefix, '').replace('(', '').replace(')', '')

            # Normalize separators
            original_name_cleaned = re.sub(r'[ ._-]+', '_', original_name_cleaned).strip('_')

            # Construct new filename with timestamp prefix and original name suffix
            new_filename_base = f"{timestamp_prefix}-{original_name_cleaned}"
            new_filename_base = new_filename_base.strip('_').strip('-').strip()
        
            if new_filename_base == original_name:
                continue

            new_filename = f"{new_filename_base}{lower_extension}"
            new_file_path = os.path.join(folder_path, new_filename)

            # check for name collisions
            if os.path.exists(new_file_path):
                raise Exception(f"{new_filename} already exists")

            count_renamed += 1

            if dry_run:
                print(f"[RENAMING] {count:>{5}}   {file_name:<{60}} {new_filename}")    
            else:
                os.rename(file_path, new_file_path)
                logs.append(f"Renamed ; '{file_name}' ; '{new_filename}'")

        print(f"==== counts: total:{count_total}    parsed:{len(metadata_list)}    ok:{count_ok}    renamed:{count_renamed}    error:{len(errors)})")
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

def main():
    try:
        parser = argparse.ArgumentParser(
            description="Tool to organize media files.",
            epilog="Example: python main.py /path/to/photos --rename --debug"
        )
        parser.add_argument("folder_path", help="The path to the folder containing the media files.")
        parser.add_argument("--debug", action="store_true", help="More verbose.")
        parser.add_argument("--dry-run", action="store_true", help="No file modification / deletion is done.")
        parser.add_argument("--rename", action="store_true", help="Rename media files using their metadata timestamp.")
        parser.add_argument("--delete-dups", action="store_true", help="Find duplicate files in the folder based on checksum.")
        parser.add_argument("--flatten", action="store_true", help="Move all files from subdirectories to the root folder and remove empty subdirectories.")
        parser.add_argument("--timezone", help="Specify a timezone (e.g., 'Europe/Paris') to use for UTC conversion when GPS data is missing.")
        args = parser.parse_args()

        if args.flatten:
            flatten_directory(folder_path=args.folder_path, dry_run=args.dry_run)

        if args.delete_dups:
            process_duplicate_files(folder_path= args.folder_path, dry_run=args.dry_run, debug=args.debug)
            
        if args.rename:
            rename_media(folder_path= args.folder_path, timezone=args.timezone, dry_run=args.dry_run, debug=args.debug)

    except Exception as ex:
         print('=== FATAL ERROR')
         print(traceback.format_exc())

if __name__ == "__main__":
    main()