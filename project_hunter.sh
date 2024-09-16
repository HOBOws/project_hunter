#!/bin/bash

#full functionality of this script require VirusTotal API key, and SplunkForwarder and requre the user manual installation/registration. however this script can be used without them for documenting communication and file hashes.


# Global variables
tool=$(pwd)
pcaps=$tool/pcaps
archive=$pcaps/archive
objects=$tool/objects
metadata=$objects/metadata
meta_archive=$metadata/meta_archive

# Color codes
red='\e[0;31m'
grn='\e[0;32m'
norm='\e[0;0m'
yel='\e[0;33m'
cyan='\e[0;36m'



# Banner function
function Banner() {
    echo -e "${grn}"
    figlet "Project: HUNTER"
    echo -e "A live malice detection tool by Daniel Ben-Yehuda ${norm}"
    date
    sleep 2
}
Banner

# Dependencies check
function dependencies() {
    # Create directories if they do not exist
    mkdir -p "$pcaps" "$meta_archive" "$archive" "$objects" "$metadata" 
    echo "[-] Checking for gnome-terminal" 
    sudo apt-get install gnome-terminal > /dev/null 2>&1

    # Check if CapTipper.py exists
    cap=$(locate CapTipper.py | grep -v cache)
    if [ -z "$cap" ]; then
        echo "[-] Downloading CapTipper to $(pwd)..."
        git clone https://github.com/omriher/CapTipper.git > /dev/null 2>&1
        echo "[-] Updating DB..."
        sudo updatedb
    fi
}
dependencies

function splunk_forwarder () { #asks if splunk is neede. if so, adds the VT response for confirmed malware and all md5sum to be forwarded to splunk 
    echo -e "This script can forward events to splunk, would you like to configure this option? (press no if it is already configured or you do not wish to use this).\n[y]es\n[ENTR] move on!"
    read -s  -p ":: " SF
    if [ $SF == "y" ]; then
        splunk=$(locate /splunkforwarder/bin/splunk | head -1)
        echo -e "${grn}Configuring splunk forwarder directory${norm}"
        sudo $splunk add monitor $meta_archive
        sudo $splunk add monitor $metadata
        sudo $splunk restart
    else 
        echo "Moving on"
    fi

}
splunk_forwarder

# VirusTotal API integration function
function VT() {
    echo -e "[-] For full functionality, this script requires VirusTotal API integration to CapTipper [-]${red}"
    figlet "! WARNING !"
    echo -e "${yel}This script gives the user the option to either use or skip VirusTotal. The VirusTotal API key has limited usage and can quickly reset your tokens."
    echo -e "\nAPI :: To use VirusTotal, please enter API key\n[ENTR] to use without VirusTotal\n"
    read -p ":: " API
    echo "$API" > "$tool/API.txt"
}
VT

# Logger function
function logger() { #captures network communication in 25 seconds duration to be analyzed
    gnome-terminal --title="Logger" -- bash -c "
        while true; do
            timestamp=\$(date +'%Y-%m-%d_%H-%M-%S-%3N')
            echo -e '${red}Logger is up!${norm}'
            tshark -i eth0 -a duration:25 -w $pcaps/\${timestamp}.pcap
            sleep 1
        done
        exec bash"
}
logger

# Blacklist Monitor function - searches for communication with IoC by list and alerts in real time.
function BlackList_monitor() {
    gnome-terminal --title="Black List Monitor - IoC" -- bash -c "
        echo -e '${red}[-] Black List Monitor [-]${norm}';

        FILTER='';

        for IP in \$(echo \$(curl -s https://feeds.dshield.org/top10-2.txt | awk '{print \$1}')); do
            if [ -n \"\$FILTER\" ]; then
                FILTER=\"\$FILTER or \";
            fi
            FILTER=\"\$FILTER(ip.src == \$IP or ip.dst == \$IP)\";
        done;

        tshark -i eth0 -Y \"\$FILTER\" -T fields -e frame.time -e ip.proto -e ip.src -e ip.dst -e dns.qry.name -e http.request.full_uri -e http.response.code;
        exec bash"
}
BlackList_monitor

# File analysis function
function File_Analysis() {
    while true; do
        # Analyze new pcaps
        for pcap in $(ls "$pcaps" | grep -v archive); do
            python2 $(locate CapTipper.py | grep -v cache) "$pcaps/$pcap" -d "$objects" > /dev/null 2>&1
        done

        # Generate and store file hashes
        date >> "$metadata/hashes-$(date | sed 's/ /-/g').txt" 2>/dev/null
        for file in $(ls $objects | grep -v metadata); do
            md5sum "$objects/$file" >> "$metadata/hashes-$(date | sed 's/ /-/g').txt"
        done

        rm "$objects/"* > /dev/null 2>&1

        # VirusTotal integration
        if [ -s "$tool/API.txt" ]; then
            for hash in $(awk 'NR>1 {print $1}' "$metadata/hashes-"*.txt); do
                curl -s -X POST 'https://www.virustotal.com/vtapi/v2/file/report' \
                    --form apikey="$(cat "$tool/API.txt")" \
                    --form resource="$hash" | sed 's|\},|\}\n|g' >> "$meta_archive/meta-$(date | sed 's/ /-/g').txt"
                sleep 3
            done
        fi

        # Move processed files to archive
        mv "$metadata/"*.txt "$meta_archive" > /dev/null 2>&1
        mv "$pcaps/"*.pcap "$archive" > /dev/null 2>&1
        mv "$pcaps/"*.pcapng "$archive" > /dev/null 2>&1

        # Check for malware detection in reports
        for report in "$meta_archive/"*; do
            if grep -q -e '"detected":true' "$report" 2>/dev/null; then
                echo -e "${red}MALWARE DETECTED IN REPORT: ${norm}$report"
            else
                rm "$report" 2>/dev/null
            fi
        done

        # Remove empty files
        for file in "$meta_archive/"*; do
            if [ -f "$file" ] && [ $(wc -l < "$file") -le 1 ]; then
                rm "$file" > /dev/null 2>&1
            fi
        done

    done
}
File_Analysis
