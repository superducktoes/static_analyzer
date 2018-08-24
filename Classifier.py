import pickle

class Classifier:

    def __init__(self):
        self.dumped_classifier = "./classifier_data/dumped_classifier.pkl"

    def load_dumped_classifier(self):

        #prediction = clf.predict([[17920, 4, 33088, 6, 97312]])
        with open(self.dumped_classifier, 'rb') as fid:
            clf = pickle.load(fid)
            
        return clf
