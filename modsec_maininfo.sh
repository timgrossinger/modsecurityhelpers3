#!/bin/bash

logpath=/var/log/modsec_audit/www-data/$(date +%Y%m%d)

# The story:
# - when modsecurity is set to "on" but with a high anomaly threshold in order to NOT intercept the request (kind of like audit mode) it does not actually write the anomaly score into the log file.
#   rule 2001099 changes this
# - this change is needed for this script to work, as it greps for the added log content.
# - this script just gives information about a particular message like "Remote Command Execution: Unix Shell Expression Found"

# Requirements: 
# - CoreRuleSet 3.3.2
# - Rule 2001099 that is run AFTER the rules of CoreRuleSet (defined in apache-mods/security2.conf)
# - SecAuditLogType should be set to Concurrent" (/etc/modsecurity/modsecurity.conf)
#     SecAuditLogType Concurrent
#     SecAuditLogStorageDir /var/log/modsec_audit

# Tested with modsecurity 3.2.0
# Ubuntu 20.04
# Apache


### INSTRUCTION ###

# Run the following command in $logpath before this script, to show the messages of the rules that raised the anomaly score and their number of occurence:
# grep -rHlP "Total Score:\ \d+" | xargs -I{} grep -hP '^Message.*\[msg.+?\]' {} | grep -hPo '\[msg.+?\]' | sort | uniq -c | sort -h

# Then Run this script
# Either like this:
# msg="Remote Command Execution: Unix Shell Expression Found" ./modsec_maininfo.sh 
#
# or like this:
# export msg="Remote Command Execution: Unix Shell Expression Found"
# ./modsec_maininfo.sh

echo -e "Findings about:\n \e[31m$msg\e[0m \n\n"

grep -rHlP "Total Score:\ \d+" $logpath | xargs -I{} grep -rlE "^Message.*$msg" {}
echo -e "\n"
grep -rHlP "Total Score:\ \d+" $logpath | xargs -I{} grep -rlE "^Message.*$msg" {} | xargs -I {} grep -A1 '\-B\-\-' {} | grep -vE '^-' | sort | uniq
echo -e "\n"
grep -rHlP "Total Score:\ \d+" $logpath | xargs -I{} grep -rlE "^Message.*$msg" {} | xargs -I {} grep -A1 '\-A\-\-' {} | awk '{print $4}' | sort | uniq | xargs -I{} host {}
echo -e "\n"
grep -rHlP "Total Score:\ \d+" $logpath | xargs -I{} grep -rlE "^Message.*$msg" {} | xargs -I{} grep -oe "^Message.*$msg.*" {} | grep -oE "id\ \"[0-9]{6}\"" | sort | uniq
echo -e "\n"
grep -rHlP "Total Score:\ \d+" $logpath | xargs -I{} grep -rlE "^Message.*$msg" {} | xargs -I{} grep -oe "^Message.*$msg.*" {} | sed "s/^Message.*Matched\ Data:\ //" | cut -d[ -f1 | sort | uniq
