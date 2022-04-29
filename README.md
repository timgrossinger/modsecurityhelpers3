# modsecurityhelpers
Helpers for modsecurity Logs

 The story:
 - when modsecurity is set to "on" but with a high anomaly threshold in order to NOT intercept the request (kind of like audit mode) it does not actually write the anomaly score into the log file.
   rule 2001099 changes this
 - this change is needed for the script modsec_maininfo.sh to work, as it greps for the added log content.
 - this script just gives information about a particular message like "Remote Command Execution: Unix Shell Expression Found"

 Requirements:
 - CoreRuleSet 3.3.2
 - Rule 2001099 that is run AFTER the rules of CoreRuleSet (defined in apache-mods/security2.conf)
 - SecAuditLogType should be set to Concurrent" (/etc/modsecurity/modsecurity.conf)
     SecAuditLogType Concurrent
     SecAuditLogStorageDir /var/log/modsec_audit

 Tested with modsecurity 3.2.0
 Ubuntu 20.04
 Apache


### INSTRUCTION ###

 Clone Repository and add executable bit:
 - git clone https://github.com/stefanpinter/modsecurityhelpers.git
 - cd modsecurityhelpers
 - chmod +x modsec_maininfo.sh

 Run the following command in $logpath before this script, to show the messages of the rules that raised the anomaly score and their number of occurence:
 grep -rHlP "Total Score:\ \d+" | xargs -I{} grep -hP '^Message.*\[msg.+?\]' {} | grep -hPo '\[msg.+?\]' | sort | uniq -c | sort -h

 Then Run this script
 Either like this:
 msg="Remote Command Execution: Unix Shell Expression Found" ./modsec_maininfo.sh

 or like this:
 export msg="Remote Command Execution: Unix Shell Expression Found"
 ./modsec_maininfo.sh
