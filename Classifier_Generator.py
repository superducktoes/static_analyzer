from sklearn import tree
#from sklearn.neighbors import KNeighborsClassifier
#from sklearn import svm

import pickle

class Classifier_Generator:

    def __init__(self):
        self.path_to_features = "./classifier_data/features_data"
        self.path_to_labels = "./classifier_data/labels_data"
        # list of features lists
        self.features = []
        # empty list to populate with labels
        # 1 is for malware 0 is good
        self.labels = []

    def load_features_labels(self):
        
        # populate a list from the file
        with open(self.path_to_features, "r") as fp:
            line = fp.readline()

            while line:
                inner_list = []
                stripped_line = line.strip()
                stripped_line = stripped_line[1:]
                stripped_line = stripped_line[:len(stripped_line)-1]
                stripped_line = stripped_line.split(",")
                #print(stripped_line)
                for i in stripped_line:
                    i = i.strip()
                    inner_list.append(float(i))
                #print(inner_list)
                self.features.append(inner_list)
                line = fp.readline()
        print(self.features)
        with open(self.path_to_labels) as fp:
            line = fp.readline()
            while line:
                self.labels.append(int(line))
                line = fp.readline()
        print(self.labels)
    def get_classifier_features(self):
        return self.features

    def get_classifier_labels(self):
        return self.labels

    def generate_save_classifier(self):
        clf = tree.DecisionTreeClassifier(criterion='gini', max_features=4, max_depth=16)
        #clf = KNeighborsClassifier(n_neighbors=5)
        #clf = svm.SVC(kernel='sigmoid')
        clf = clf.fit(self.features,self.labels)
        
        with open('./classifier_data/dumped_classifier.pkl', 'wb') as fid:
            pickle.dump(clf, fid)


    def add_new_feature_label(self, feature_list, label):
        if feature_list is not None:
            hs = open(self.path_to_features, "a")
            hs.write("\n")
            hs.write(str(feature_list))
            hs.close()

            hs = open(self.path_to_labels, "a")
            hs.write("\n")
            hs.write(str(label))
            hs.close()
            
