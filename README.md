@'

AUTHORIZED NETWORK PORT SCANNER



TASK 4 - B.Y.T.E CYBERSECURITY INTERNSHIP



A Python-based TCP port scanner designed for scanning localhost or other explicitly authorized systems.



FEATURES



\- Scans a configurable IP address or hostname.

\- Scans a configurable TCP port range.

\- Reports open, closed, and filtered ports.

\- Uses concurrent scanning with configurable workers.

\- Detects common TCP service names for open ports.

\- Displays scan progress and summary.

\- Generates structured CSV and JSON reports.

\- Records timestamp and scan parameters.

\- Validates target and port range.

\- Includes connection timeout configuration.



REQUIREMENTS



\- Python 3

\- No external Python packages are required.



USAGE



Basic Scan:



python .\\port\_scanner.py 127.0.0.1 1 100



Scan a Single Port:



python .\\port\_scanner.py 127.0.0.1 8000 8000



Custom Timeout:



python .\\port\_scanner.py 127.0.0.1 1 100 --timeout 2



Custom Number of Workers:



python .\\port\_scanner.py 127.0.0.1 1 100 --workers 25



EXAMPLE TEST



A local HTTP server was started on port 8000:



python -m http.server 8000



The scanner was then executed:



python .\\port\_scanner.py 127.0.0.1 8000 8000



Expected result:



\[OPEN] Port: 8000

Open Ports      : 1

Closed Ports    : 0

Filtered Ports  : 0



OUTPUT



Reports are automatically saved in the reports directory.



CSV



Contains:



\- Timestamp

\- Target

\- Port

\- Protocol

\- Status

\- Service



JSON



Contains:



\- Scan timestamp

\- Target

\- Resolved IP

\- Protocol

\- Port range

\- Timeout

\- Number of workers

\- Scan summary

\- Individual port results

\- Scan duration



PERFORMANCE



The initial sequential implementation required approximately 100 seconds to scan ports 1-100 with a 1-second timeout.



The concurrent implementation uses multiple workers and completed the same localhost test in approximately 2 seconds.



LEGAL AND ETHICAL NOTICE



This tool is intended only for educational and authorized security testing.



The scanner must only be used against:



\- Localhost systems.

\- Systems owned by the user.

\- Systems for which the user has explicit permission to perform testing.



Unauthorized port scanning may violate organizational policies or applicable laws.



All testing for this project was performed against localhost (127.0.0.1), including a locally created HTTP test service on port 8000.



PROJECT STRUCTURE



CS\_4\_AuthorizedNetworkPortScanner\_byte



&#x20;   port\_scanner.py

&#x20;   README.md

&#x20;   requirements.txt

&#x20;   sample\_output.csv

&#x20;   sample\_output.json



&#x20;   reports

&#x20;       Generated CSV and JSON reports



&#x20;   screenshots

&#x20;       01\_concurrent\_scan.png

&#x20;       02\_open\_port\_test.png

&#x20;       03\_generated\_reports.png



EVIDENCE



The screenshots directory contains evidence of:



1\. Concurrent scanning of localhost ports 1-100.

2\. Detection of an open local port 8000.

3\. Generated CSV and JSON reports.



AUTHOR



MALINI S



Cybersecurity Intern



B.Y.T.E Cybersecurity Internship - Task 4

'@ | Set-Content -Path .\\README.md -Encoding UTF8

