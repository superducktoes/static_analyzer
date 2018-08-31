import pefile
import sys
import os
import re
import codecs
from datetime import datetime

# PE_Analyzer class takes one argument the path to the file
class PE_Analyzer:

    def __init__(self, file_to_open):

        
        self.file_to_open = file_to_open
        self.file_size = os.path.getsize(file_to_open)
        self.file_section_names = []
        self.section_counter = 0
        # dictionary to store the DLL and then a list of functions imported
        self.file_libraries_imported = {}
        self.file_search_strings = {}
        self.unusual_section_counter = 0
        self.unusual_section_names = []
        # used to generate the output for our classifier
        self.ml_data = []
        
    def analyze_file(self):
        print("Analyzing File: " + self.file_to_open)

        # create new PE object to start analyzing file
        pe = pefile.PE(self.file_to_open)

        # commenting this out for now. I don't remember why I needed this if at all
        #print(pe.parse_data_directories())

        # populate a list of the file section names
        file_sections = pe.sections

        # this needs to be cleaned up and moved to a separate function
        expected_section_names = [".text", ".bss", ".rdata", ".data", ".rsrc", ".edata", ".idata", ".pdata", ".debug"]
        for i in file_sections:
            self.file_section_names.append(str(i.Name.decode("utf-8").split("\x00")[0]))
            self.section_counter = self.section_counter + 1
        for i in self.file_section_names:
            if i not in expected_section_names:
                self.unusual_section_names.append(i)
                self.unusual_section_counter = self.unusual_section_counter + 1
                
        # create a dictionary with the key of the library and the values a list of functions imported
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # get the name of the library
            library_imported = str(entry.dll.decode("utf-8"))
            functions_imported = []
            for imp in entry.imports:
                if imp.name != None:
                    # decode only once this time the name of the function
                    pe_import = str(imp.name.decode("utf-8"))
                    functions_imported.append(pe_import)
            self.file_libraries_imported[library_imported] = functions_imported

        # pass the pe object to our generate_ml_function
        self._generate_ml_output(pe)


    # takes a list of strings as a parameter to search the file for
    def search_file(self, strings_to_search):
        with codecs.open(self.file_to_open, "r", encoding="utf-8", errors="ignore") as fdata:
            for line in fdata:
                # search each line for all of the strings and update our dictionary
                for i in strings_to_search:
                    if re.search(i, line):
                        self.file_search_strings[i] = True
                    else:
                        # need this here because if not we'll always overwrite a True value if found
                        if self.file_search_strings.get(i, "None") != True:
                            self.file_search_strings[i] = False
                        

    
    # take our pe object and pass to internal function to generate list for classifier
    # moved to a separte function incase there are other items to add to the data
    def _generate_ml_output(self, pe):
        
        self.ml_data.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
        self.ml_data.append(self.section_counter)
        self.ml_data.append(self.unusual_section_counter)
        self.ml_data.append(pe.OPTIONAL_HEADER.DllCharacteristics)
        self.ml_data.append(pe.OPTIONAL_HEADER.MajorImageVersion)
        self.ml_data.append(pe.OPTIONAL_HEADER.CheckSum)
        

    def get_unusual_section_names(self):
        return self.unusual_section_names, self.unusual_section_counter

    def get_suspicious_imports(self):
        suspicious_imports = ["URLDownloadToFileA", "ShellExecuteA", "CreateThread", "FindFirstFileA", "LoadLibraryA", "RegDeleteKeyW","GetProcAddress", "ExitProcess", "GetModuleFileNameA", "WriteConsoleW"]
        file_suspicious_imports = []
        
        # this is a little ugly but take each element of the suspicious_imports list and search our
        # dictionary we created earlier to see if there are any matches
        for i in suspicious_imports:
            for j in self.file_libraries_imported:
                for k in self.file_libraries_imported[j]:
                    if i in k:
                        file_suspicious_imports.append(i)
                        
        # returns a dictionary of any imports discovered that match our suspicious list                
        return file_suspicious_imports

    # this sort of works but needs a lot more information
    def get_compile_type(self):
        compiler_type = ""
        for i in self.file_libraries_imported:
            if i == "MSVBM60.DLL":
                compiler_type = "VB 6"
            else:
                compiler_type = "Not really sure"
                
        return compiler_type
            
    def get_ml_output(self):
        return self.ml_data
    
    # print the list of file section names
    def get_file_section_names(self):
        return self.file_section_names

    def get_file_section_counter(self):
        return self.section_counter

    def get_file_libraries_imported(self):
        return self.file_libraries_imported

    def get_file_search_strings(self):
        return self.file_search_strings

    def get_file_size(self):
        return self.file_size
