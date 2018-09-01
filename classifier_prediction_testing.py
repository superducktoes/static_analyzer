import pickle
import pydotplus
from sklearn.externals.six import StringIO
from IPython.display import Image
from sklearn.tree import export_graphviz
import sys

features = [
    [356352, 9, 3, 0, 0, 989180],
    [0, 1, 0, 0, 0, 0],
    [1536, 3, 1, 34112, 0, 0],
    [239104, 11, 4, 35168, 0, 864605],
    [83456, 5, 1, 33088, 0, 233036],
    [186368, 9, 3, 0, 0, 815036],
    [26624, 5, 1, 0, 0, 0],
    [86528, 9, 3, 0, 0, 0],
    [32768, 3, 2, 0, 7, 0],
    [206848, 3, 0, 32768, 0, 0],
    [4096, 3, 2, 0, 0, 0],
    [4096, 3, 2, 0, 0, 0],
    [11776, 8, 5, 0, 0, 0],
    [64000, 6, 2, 33024, 0, 1012312],
    [141824, 5, 1, 34112, 6, 4111926],
    [8303616, 7, 3, 33088, 0, 13643179],
    [2318336, 9, 3, 320, 0, 19329605],
    [392192, 4, 0, 0, 2, 873180],
    [67584, 3, 1, 34112, 0, 3264535],
    [40960, 3, 2, 33088, 0, 7893014]
]
labels = [1,1,1,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0]

with open("./classifier_data/dumped_classifier.pkl", "rb") as fib:

    pickle_model = pickle.load(fib)

score = pickle_model.score(features, labels)
print("Test score: {0:.2f} %".format(100 * score))
Ypredict = pickle_model.predict(features)
print("prediction: ")
print(Ypredict)
print("actual: ")
print(labels)


dot_data = StringIO()
export_graphviz(pickle_model, out_file=dot_data, filled=True, rounded=True, special_characters=True)
graph = pydotplus.graph_from_dot_data(dot_data.getvalue())
graph.write_pdf("decision_tree_classifier.pdf")
