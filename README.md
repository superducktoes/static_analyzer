Static file analyzer built around the research of Yibin Liao http://cobweb.cs.uga.edu/~liao/PE_Final_Report.pdf
<br>
Eventual goal is to build ML classifier for discovering PE malware with static analysis
<br>
Additional information from the following: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.302.4567&rep=rep1&type=pdf

<br>
Classifer built with scikit and testing with the following results:
<br>
clean files - 80%
<br>
malicious files - 82%
<br>
files marked as evasive on h-a: 28%

<br>
main.py shows example of how Static_Analysis can be imported and used to generate data for classifier. Working on cleaning up classifier code to commit also.
