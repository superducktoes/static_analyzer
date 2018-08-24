from sklearn import tree
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
        with open(self.path_to_features) as file:
            for line in file:
                # this might be a little ugly. Since the
                # file reads in as a string we need to drop
                # the brackets and split on the commas
                line = line[1:]
                line = line[:len(line)-2]
                line = line.split(",")
                inner_list = []
                
                for i in line:
                    # the point of this is to drop the
                    # space in front of the comma if its
                    # there
                    if i != ",":
                        inner_list.append(float(i))
                    elif i != "," and " " in i:
                        inner_list.append(float(i[1:]))
                    # add the list to the main list
                self.features.append(inner_list)

        with open(self.path_to_labels) as file:
            for line in file:
                self.labels.append(int(line))

    def get_classifier_features(self):
        return self.features

    def get_classifier_labels(self):
        return self.labels

    def generate_save_classifier(self):
        clf = tree.DecisionTreeClassifier()
        clf = clf.fit(self.features,self.labels)
        
        with open('./classifier_data/dumped_classifier.pkl', 'wb') as fid:
            pickle.dump(clf, fid)


    def add_new_feature_label(self, feature_list, label):
        with open(self.path_to_features, "a") as file:
            file.write(str(feature_list))

        with open(self.path_to_labels, "a") as file:
            file.write(str(label))
