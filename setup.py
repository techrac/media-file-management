import sys
import os
import shutil
import zipfile
from datetime import datetime
from cx_Freeze import setup, Executable
import exiftool  # To find the executable


def get_package_path(package_name):
    """A helper function to find the path of an installed package."""
    import importlib.util
    try:
        spec = importlib.util.find_spec(package_name)
        if spec is None or spec.origin is None:
            raise ImportError
        # For packages, the origin is often __init__.py, so we need the parent dir
        return os.path.dirname(spec.origin)
    except ImportError:
        raise ImportError(
            f"Could not find the '{package_name}' package. Is it installed?"
        )

def zip_app_bundle(app_path, output_dir="build"):
    """Create a zip file of the app bundle for distribution."""
    if not os.path.exists(app_path):
        print(f"Warning: App bundle not found at {app_path}")
        return None
    
    # Create timestamp for the zip file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    app_name = os.path.basename(app_path).replace('.app', '')
    zip_filename = f"{app_name}_{timestamp}.zip"
    zip_path = os.path.join(output_dir, zip_filename)
    
    print(f"Creating distribution zip: {zip_filename}")
    
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through all files in the app bundle
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Calculate the relative path within the zip
                    arcname = os.path.relpath(file_path, os.path.dirname(app_path))
                    zipf.write(file_path, arcname)
        
        # Get zip file size for reporting
        zip_size = os.path.getsize(zip_path) / (1024 * 1024)  # Size in MB
        print(f"✅ Distribution zip created: {zip_filename} ({zip_size:.1f} MB)")
        return zip_path
        
    except Exception as e:
        print(f"❌ Error creating zip file: {e}")
        return None

# --- Find required data and binaries ---

# 1. Find the exiftool executable provided by PyExifTool
try:
    with exiftool.ExifToolHelper() as et:
        exiftool_path = et.executable
    # The tuple is (source_path, destination_in_bundle)
    exiftool_include = (exiftool_path, os.path.basename(exiftool_path))
except Exception as e:
    print(f"Warning: Could not find the exiftool executable: {e}")
    exiftool_include = None

# 2. Find the data files for timezonefinder
try:
    tz_path = get_package_path('timezonefinder')
    tz_include = (tz_path, 'timezonefinder')
except Exception as e:
    print(f"Warning: Could not find timezonefinder data files: {e}")
    tz_include = None

# 3. Find the data files for tzdata
try:
    tzdata_path = get_package_path('tzdata')
    tzdata_include = (tzdata_path, 'tzdata')
except Exception as e:
    print(f"Warning: Could not find tzdata files: {e}")
    tzdata_include = None

# --- Build Configuration ---

# Files and directories to include in the build. Filter out any that were not found.
include_files = [f for f in [exiftool_include, tz_include, tzdata_include] if f is not None]

# Packages that cx_Freeze might miss.
packages = ["tkinter", "numpy", "exiftool", "zoneinfo", "main"]

build_exe_options = {
    "packages": packages,
    "include_files": include_files,
    "excludes": [],
}

# For macOS, we need to specify bdist_mac options to create a proper .app
bdist_mac_options = {
    "bundle_name": "MediaTool",
}

# Set the base for a GUI application.
# On Windows, this should be "Win32GUI" to hide the console.
# On macOS, we set it to None and let the `bdist_mac` command handle creating the .app bundle.
base = "Win32GUI" if sys.platform == "win32" else None

# Define the executable
executables = [
    Executable("gui.py", base=base, target_name="MediaTool")
]

# --- Setup ---
setup(
    name="MediaTool",
    version="1.0",
    description="A tool to organize media files.",
    options={"build_exe": build_exe_options, "bdist_mac": bdist_mac_options},
    executables=executables,
)

# --- Post-build step: Create distribution zip ---
if __name__ == "__main__" and len(sys.argv) > 1 and "bdist_mac" in sys.argv:
    # Only run post-build step when building macOS app
    app_path = os.path.join("build", "MediaTool.app")
    if os.path.exists(app_path):
        print("\n" + "="*50)
        print("POST-BUILD: Creating distribution package...")
        print("="*50)
        zip_path = zip_app_bundle(app_path)
        if zip_path:
            print(f"📦 Ready for distribution: {os.path.basename(zip_path)}")
        print("="*50)
    else:
        print("Warning: MediaTool.app not found, skipping zip creation")