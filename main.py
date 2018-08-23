#import Static_Analyzer from file_pe_detection
#from file_pe_detection import Static_Analyzer
from Static_Analyzer import PE_Analyzer

if __name__ == "__main__":

    file_to_analyze = PE_Analyzer("./test_mal.bin")
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
