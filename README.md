# modsecurityhelpers
Helpers for modsecurity Logs
### The story ### - when modsecurity is set to "on" but with a high anomaly threshold in order to NOT intercept the request (kind of like audit mode) it does not actually write the anomaly score into the log file.
   rule 2001099 changes this
 - this change is needed for the script modsec_maininfo.sh to work, as it greps for the added log content.
 - this script just gives information about a particular message like "Remote Command Execution: Unix Shell Expression Found"

### Requirements ###
 - modsecurity 2.9.2
 - CoreRuleSet 3.3.2
 - Rule 2001099 that is run AFTER the rules of CoreRuleSet (defined in apache-mods/security2.conf)
 - SecAuditLogType should be set to Concurrent" (/etc/modsecurity/modsecurity.conf)
     SecAuditLogType Concurrent
     SecAuditLogStorageDir /var/log/modsec_audit

### Tested with modsecurity 2.9.2 ###
 - CoreRuleSet 3.3.2
 - Ubuntu 20.04
 - Apache


### INSTRUCTION ###

 Clone Repository and add executable bit:
```
git clone https://github.com/stefanpinter/modsecurityhelpers.git
cd modsecurityhelpers
chmod +x modsec_maininfo.sh
```

Run this script
```
 ./modsec_maininfo.sh
```

It searches for the messages in the logs.
The messages and their number of occurence is shown.
Choose the message you want info about.

It will present you 
- the matching logfiles
- information about the request header (for example GET /drupal/setup.php)
- the PTR record of the IP of the http client (if there is one)
- the id of the matchin rule
- information about what matched
