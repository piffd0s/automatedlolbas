This script is intended to automate further lolbas research based on the work of the pentera team. https://pentera.io/resources/research/the-lolbas-odyssey-finding-new-lolbas-and-how-you-can-too/

This script will take all of your collected exes from a research directory and have ida pro parse them in batch mode. once in batch mode the script will look for the following api calls

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

file_write_apis = [
    "WriteFile",
    "fwrite",
    "CreateFile",
    "CloseHandle",
    "open",
    "write",
    "fclose"
]

if those are found they will be logged to a logfile for further analysis. this script can be modified to look for the api calls that you are looking for specifically.

additional work can be done to ensure that web downloads are user controllable as well as file writes.
