import sys
import os
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
