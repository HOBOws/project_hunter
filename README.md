This is a student IDS with 3 functions:
1. live monitor network traffic for IoC by utilizing Tshark.
2. documenting network traffic with Tshark.
3. extracting files passing through the network by utilizing CupTipper..
(optional): analyzing extracted files for malware by utilizing VirusTotal API with curl.
(optional): send report of confirmed malware (detected by VT) with Splunk forwarder. 

Dependencies:
updated system
gnome-terminal - apt-get install gnome-terminal
CupTipper - https://github.com/omriher/CapTipper.git 
Tshark - sudo apt install tshark

For optional functions register at virustotal.com and  splunk.com
