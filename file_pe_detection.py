import pefile
import sys

# fileName = "/home/pi/malware_ma/samples/" + str(sys.argv[1])
fileName = str(sys.argv[1])
vb_compiled = False

# final score tallied to determine if the indicators show it to be malware
malware_score = 0

# create a list of suspicious imports to search for
# empty dictionary created now to populate at the end
suspicious_imports_found = {}
suspicious_imports = ["URLDownloadToFileA", "ShellExecuteA", "CreateThread", "FindFirstFileA", "GetProcAddress", "LoadLibraryA"]
suspicious_imports_counter = 0

for i in suspicious_imports:
    suspicious_imports_found[i] = False

print(fileName)

# create the new pefile object
pe = pefile.PE(fileName)

# print out the headers
print(pe.FILE_HEADER)
print(pe.OPTIONAL_HEADER)

print(pe.parse_data_directories())

file_sections = pe.sections

# decode and print out the sections
header_counter = 0
section_names = []
for i in file_sections:
    print(i)
    section_names.append(str(i.Name.decode('utf-8')))
    header_counter = header_counter + 1

file_imports = {}
pe.parse_data_directories()

# parse and print the imports
# clean this up to not spend time decoding each time

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    api_list = []
    print("\n" + str(entry.dll.decode('utf-8')) + "\n")

    # check to see if compiled with VB
    if entry.dll == b"MSVBVM60.DLL":
        vb_compiled = True

    for imp in entry.imports:
        if imp.name != None:
            print(str(imp.name.decode('utf-8')))
            api_list.append(str(imp.name.decode('utf-8')))
            if(imp.name.decode('utf-8') in suspicious_imports):
                suspicious_imports_found[imp.name.decode('utf-8')] = True
                suspicious_imports_counter = suspicious_imports_counter + 1
                
        file_imports[str(entry.dll.decode('utf-8'))] = str(api_list)
    
print("========== + REPORT + ==========")
if vb_compiled:
    print("Note -> Written and compiled with VB. This may throw things off.")

print("\nTotal Section Headers: " + str(header_counter))
print("\nMajorImageVersion: " + str(pe.OPTIONAL_HEADER.MajorImageVersion))
print("\nCheckSum: " + str(pe.OPTIONAL_HEADER.CheckSum))
print("\nDllCharacteristics: " + str(pe.OPTIONAL_HEADER.DllCharacteristics))
print("\nSizeOfInitializedData: " + str(pe.OPTIONAL_HEADER.SizeOfInitializedData))
print("\nSuspicious Imports Found: " + str(suspicious_imports_found))
print("\nSection Names: " + str(section_names))
print("\nImports: " + str(file_imports))

'''
if not vb_compiled:
    if(header_counter < 9 or
       (pe.OPTIONAL_HEADER.MajorImageVersion < 1 and
        pe.OPTIONAL_HEADER.CheckSum < 1 and
        pe.OPTIONAL_HEADER.MajorImageVersion < 1)):
        print("\n\n probably malware \n")
    else:
        print("\n\n probably not malware \n\n")
'''
# these two things have nothing to do with each other right now...

if not vb_compiled:
    if(header_counter <= 9):
        malware_score = malware_score + 1
    if(pe.OPTIONAL_HEADER.MajorImageVersion < 1):
        malware_score = malware_score + 1
    if(pe.OPTIONAL_HEADER.CheckSum < 1):
        malware_score = malware_score + 1
    if(pe.OPTIONAL_HEADER.DllCharacteristics < 1):
        malware_score = malware_score + 1
    if(pe.OPTIONAL_HEADER.SizeOfInitializedData < 1):
        malware_score = malware_score + 1
    if(suspicious_imports_counter >= 3):
        malware_score = malware_score + 1
        
    print("Malware score: " + str(malware_score))
    if(malware_score >= 4):
        print("\n\n probably malware")
    else:
        print("\n\n probably not malware")