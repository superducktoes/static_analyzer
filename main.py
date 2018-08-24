from Static_Analyzer import PE_Analyzer
from Classifier_Generator import Classifier_Generator
from Classifier import Classifier

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
        print("\n\n\n\n ++++ Testing Updating the classifier ++++ \n\n\n")

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
