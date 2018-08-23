from Static_Analyzer import PE_Analyzer
import sys

if __name__ == "__main__":

    if sys.argv[1]:
        file_to_analyze = PE_Analyzer(sys.argv[1])
        file_to_analyze.analyze_file()
        file_to_analyze.search_file(["Sleep", "GetKeyBoardState", "OpenSCManager"])
        print(file_to_analyze.get_file_section_names())
        print(file_to_analyze.get_file_section_counter())
        print(file_to_analyze.get_file_libraries_imported())
        print(file_to_analyze.get_file_search_strings())
        print(file_to_analyze.get_ml_output())
        print(file_to_analyze.get_unusual_section_names())
        print(file_to_analyze.get_suspicious_imports())
        print(file_to_analyze.get_compile_type())
    else:
        print("Usage: python3 main.py /path/to/malicious/file.exe")
