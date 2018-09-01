<h1>Static Analyzer</h1>
Static file analyzer built around the research of Yibin Liao http://cobweb.cs.uga.edu/~liao/PE_Final_Report.pdf
<br>
Additional information from the following: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.302.4567&rep=rep1&type=pdf
<br>
Static analyzer analyzes a pe file looking for indicators from the above noted research. Using the indicators a machine learning classifier with scikit is created in order to better identify malicious pe's. 
<br>
main.py contains examples of analyzing the file, updating the ml classifier, and prediciting whether or not a file is malicious based on the classifier generated.
<br>
<h2>Usage</h2>
pi@raspberrypi:~/malware_ma $ python3 main.py test_mal.bin
<br>
Analyzing File: test_mal.bin
<br>
[11776, 8, 0, 0, 0]
<br>
Do you want to check for malware update the ml classifier?
<br>
1. Test for malware
<br>
2. Update classifier
<br>
: 1
<br>
probably malware
<br>
Do you want to add the analysis to the classifier?
<br>
Y or N: n
<br>
Not adding to classifier data
<hr>
<br>
Starting to see decent results when testing files. Classifier built with 90 malicious samples and 78 clean samples.
<br>
pi@raspberrypi:~/malware_ma $ python3 testing_classifier.py
<br>
Test score: 88.89 %