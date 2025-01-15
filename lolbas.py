import os
import idaapi
from idautils import Strings, Functions
from idc import get_func_name, get_segm_name, set_cmt, set_color, CIC_ITEM
from ida_funcs import get_func

# List of WinHTTP API functions to search for
winhttp_apis = [
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpCloseHandle",
    "WinHttpSetOption",
    "WinHttpQueryDataAvailable",
    "WinHttpReadData"
]

# List of File Writing API functions to search for
file_write_apis = [
    "WriteFile",
    "fwrite",
    "CreateFile",
    "CloseHandle",
    "open",
    "write",
    "fclose"
]

# Define colors
COLOR_STRING = 0x00FF00    # Green for strings
COLOR_WINHTTP = 0x0000FF   # Blue for WinHTTP API calls
COLOR_FILEWRITE = 0xFF0000 # Red for file-writing API calls

# Path to output logs
output_directory = "C:\\research\\analysis_logs"
os.makedirs(output_directory, exist_ok=True)


def log_message(log_file, message):
    """
    Logs a message to the console and a file.
    """
    print(message)
    with open(log_file, "a") as f:
        f.write(message)


def analyze_executable(log_file):
    """
    Performs the analysis for the currently loaded executable.
    """
    def search_for_string(target_string):
        strings = Strings()
        found_count = 0
        for string in strings:
            if target_string in str(string):
                module_name = get_segm_name(string.ea)
                found_count += 1
                log_message(
                    log_file,
                    f"[STRING] Found: '{string}' at 0x{string.ea:X} in module '{module_name}'\n"
                )
                set_color(string.ea, CIC_ITEM, COLOR_STRING)
        return found_count

    def search_for_functions(target_functions, category, color):
        found_count = 0
        for func_name in target_functions:
            for ea in Functions():
                name = get_func_name(ea)
                if func_name in name:
                    module_name = get_segm_name(ea)
                    found_count += 1
                    log_message(
                        log_file,
                        f"[{category.upper()}] Found: {func_name} at 0x{ea:X} in module '{module_name}'\n"
                    )
                    set_color(ea, CIC_ITEM, color)
        return found_count

    log_message(log_file, f"Analyzing executable: {idaapi.get_input_file_path()}\n")
    total_strings = search_for_string("filename")
    total_winhttp = search_for_functions(winhttp_apis, "WinHTTP", COLOR_WINHTTP)
    total_filewrites = search_for_functions(file_write_apis, "File Writing", COLOR_FILEWRITE)

    log_message(
        log_file,
        f"Summary for {idaapi.get_input_file_path()}:\n"
        f"  Strings ('filename'): {total_strings}\n"
        f"  WinHTTP functions: {total_winhttp}\n"
        f"  File-writing functions: {total_filewrites}\n\n"
    )


def main():
    """
    Main entry point for the script.
    """
    # Log file for the current executable
    executable_path = idaapi.get_input_file_path()
    log_file = os.path.join(output_directory, os.path.basename(executable_path) + ".log")

    try:
        # Perform analysis
        analyze_executable(log_file)
    except Exception as e:
        log_message(log_file, f"Error during analysis: {str(e)}\n")
    finally:
        # Save the database and exit IDA
        idaapi.save_database()
        idaapi.qexit(0)  # Gracefully close IDA


if __name__ == "__main__":
    main()
