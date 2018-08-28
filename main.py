from Static_Analyzer import PE_Analyzer
from Classifier_Generator import Classifier_Generator
from Classifier import Classifier

import sys

# takes the file_to_analyze object as a parameter in order to get analysis and run through  classifier
def analyze_file(file_to_analyze):

    # create a new classifier object based on data returned from analyzer
    new_classifier = Classifier()
    clf = new_classifier.load_dumped_classifier()
    file_to_predict = [file_to_analyze.get_ml_output()]

    # make prediction
    prediction = clf.predict(file_to_predict)

    # return whether or not we think it's malware
    if prediction[0] == 1:
        malware_status = "probably malware"
    else:
        malware_status = "probably not malware"

    return malware_status

def update_classifier(file_to_analyze, malware_status):

    new_generator = Classifier_Generator()
    # write the new values to their appropriate files
    new_generator.add_new_feature_label(file_to_analyze.get_ml_output(), malware_status)
    # load the files into memory
    new_generator.load_features_labels()
    # update the classifier and write to disk
    new_generator.generate_save_classifier()

    print("Updated classifier")
    
if __name__ == "__main__":
    
    if len(sys.argv) == 2:
        file_name = sys.argv[1]
        file_to_analyze = PE_Analyzer(file_name)
        file_to_analyze.analyze_file()
        print(file_to_analyze.get_ml_output())
        print("Do you want to check for malware update the ml classifier?")
        print("1. Test for malware ")
        print("2. Update classifier")
        choice = input(": ")

        if int(choice) == 1:
            file_status = analyze_file(file_to_analyze)

            print(file_status)
            print("Suspicious Imports: " + str(file_to_analyze.get_suspicious_imports()))
            print("Unusual Section Names: " + str(file_to_analyze.get_unusual_section_names()))
            print("Do you want to add the analysis to the classifier? ")
            choice = input("Y or N: ")
            if choice.upper() == "Y":
                print("Updating the classifer data")
                malware_status = input("Enter 1 for malicious, 0 for benign: ")
                update_classifier(file_to_analyze, int(malware_status))
            elif choice.upper() == "N":
                print("Not adding to classifier data")

        elif int(choice) == 2:
            malware_status = input("Enter 1 for malicious, 0 for benign: ")
            update_classifier(file_to_analyze, int(malware_status))

    elif len(sys.argv) == 3 and sys.argv[2] == "all":
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
        print("\n\n\n\n ++++ Testing Updating the classifier ++++ \n\n\n")
        # this is the wrong order now
        new_generator = Classifier_Generator()
        new_generator.load_features_labels()
        print(new_generator.get_classifier_features())
        print(new_generator.get_classifier_labels())
        new_generator.generate_save_classifier()
        new_generator.add_new_feature_label(file_to_analyze.get_ml_output(), 1)

        print("\n\n\n\n ++++ Testing loading the dumped classifier and predicting ++++ \n\n\n")
        new_classifier = Classifier()
        clf = new_classifier.load_dumped_classifier()
        file_to_predict = [file_to_analyze.get_ml_output()]
        prediction = clf.predict(file_to_predict)
        if prediction[0] == 1:
            print("probably malware")
        else:
            print("probably not malware")
                
    else:
        print("Usage: python3 main.py /path/to/malicious/file.exe")
