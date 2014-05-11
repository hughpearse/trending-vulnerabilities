#!/bin/bash
#
# Author:
#          Hugh Pearse
# Usage:
#          ./all.sh
#
# Description:
#          This program will calculate the CWE-id and descriptions of 
#          the most recently trending vulnerabilities in 13 lines.
#

#############
#Create CWE dictionary
#https://cwe.mitre.org/data/index.html
#############
wget --output-document=cwec_v2.6.xml.zip https://cwe.mitre.org/data/xml/cwec_v2.6.xml.zip
unzip cwec_v2.6.xml.zip

xmlstarlet sel --noblanks -t -m "//Category" -o "CWE-" -v "@ID" -o " " -v "@Name" -n cwec_v2.6.xml > cwe.txt
xmlstarlet sel --noblanks -t -m "//Weakness" -o "CWE-" -v "@ID" -o " " -v "@Name" -n cwec_v2.6.xml >> cwe.txt
xmlstarlet sel --noblanks -t -m "//Compound_Element" -o "CWE-" -v "@ID" -o " " -v "@Name" -n cwec_v2.6.xml >> cwe.txt
xmlstarlet sel --noblanks -t -m "//View" -o "CWE-" -v "@ID" -o " " -v "@Name" -n cwec_v2.6.xml >> cwe.txt

cat cwe.txt | sort -n | sed -i 'new' -e's/^/CWE-/g'

#############
#Download topical CWEs from CVE disclosures
#https://nvd.nist.gov/download.cfm
#############
wget --output-document=nvdcve-2.0-recent.xml http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-recent.xml
xmlstarlet sel -t -m "//vuln:cwe" -v "@id" -n nvdcve-2.0-recent.xml | sort | grep -v '^$' | uniq -c | sort -nr > topical-cwe.txt

#############
#List descriptions of topical vulnerabilities
#############

for i in `cat topical-cwe.txt | awk -F ' ' '{print $(NF)}'`;
do
grep "$i " cwe.txt
done
