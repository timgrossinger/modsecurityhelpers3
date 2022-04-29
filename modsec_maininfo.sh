#!/bin/bash

logpath=/var/log/modsec_audit/www-data/$(date +%Y%m%d)

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
