import os
import idaapi
from idautils import Strings, Functions
from idc import get_func_name, get_segm_name

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


def search_for_functions(target_functions):
    """
    Searches for references to specific functions in the binary.
    Returns True if any functions are found.
    """
    for func_name in target_functions:
        for ea in Functions():
            name = get_func_name(ea)
            if func_name in name:
                return True
    return False


def analyze_executable(log_file):
    """
    Analyzes the current executable and logs it only if it contains both
    file-writing API calls and HTTP requests.
    """
    has_file_writes = search_for_functions(file_write_apis)
    has_http_requests = search_for_functions(winhttp_apis)

    if has_file_writes and has_http_requests:
        log_message(
            log_file,
            f"Executable contains both file writes and HTTP requests: {idaapi.get_input_file_path()}\n"
        )
        return True  # Indicates the executable matches the criteria
    return False


def main():
    """
    Main entry point for the script.
    """
    executable_path = idaapi.get_input_file_path()
    log_file = os.path.join(output_directory, "relevant_binaries.log")

    try:
        # Perform analysis
        matches_criteria = analyze_executable(log_file)

        if matches_criteria:
            print(f"Executable matches criteria: {executable_path}")
        else:
            print(f"Executable does not match criteria: {executable_path}")

    except Exception as e:
        log_message(log_file, f"Error during analysis of {executable_path}: {str(e)}\n")
    finally:
        # Exit IDA
        idaapi.qexit(0)


if __name__ == "__main__":
    main()
