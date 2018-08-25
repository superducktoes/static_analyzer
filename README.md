	<H1>Static Analyzer</h1>
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
Analyzing File: test_mal.bin
[11776, 8, 0, 0, 0]
Do you want to check for malware update the ml classifier?
1. Test for malware
2. Update classifier
: 1
probably malware
Do you want to add the analysis to the classifier?
Y or N: n
Not adding to classifier data
<hr>
<br>
Testing Stats:
<br>
clean files - 80%
<br>
malicious files - 82%
<br>
files marked as evasive on h-a: 28%
