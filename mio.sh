#!/bin/bash
#set -x
shopt -s expand_aliases

#Define Path where the logs are
logpath=/var/log/modsec_audit/www-data/$(date +%Y%m%d)

#test: is dialog installed?
if ! which dialog > /dev/null; then
	echo ERROR
	echo Please install dialog with \"sudo apt install dialog\"
	exit 1
fi

#Reads host entries from Request Header from the logs
hosts=$(grep -rHlP "Total Score:\ \d+" ${logpath} | xargs -I{} grep -rhE '^Host' {} | grep -vE [0-9] | sort | uniq | sed 's/.*\ //')

#Adds numbers for usage with the tool dialog and removes newlines
hostsn=$(echo "${hosts}" | nl -w1 | tr '\n' ' ')

#Runs the tool dialog - choose host header to grep for (or IP adress)
chosenhostn=$(dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout 'Choose the host to filter for' 0 0 0 ${hostsn} 999 "IP address" 2>/dev/null)

#set variable chosenhost to 1 number if IP address has been chosen
if [ $chosenhostn = '999' ]; then
	chosenhost='\d{1,3}'
else
	chosenhost=$(echo "${hosts}" | sed -n ${chosenhostn}p)
fi

#Reads messages & number of occurence
messages=`grep -rHlP "^Host: $chosenhost" ${logpath} | xargs -I{} grep -rHlP "Total Score:\ \d+" {} | xargs -I{} grep -hP '^Message.*\[msg.+?\]' {} | grep -hPo '\[msg.+?\]' | sort | uniq -c | sed 's/^ *//' | sed -e 's/(/./g' | sed -e 's/)/./g' | sort -h | grep -v 'Inbound\ Anomaly' | sed -re 's/\b([0-9]+)\b.*\[msg\ \"(.*)\"\]$/\"\1 \2\"/'`

#Adds numbers for usage with the tool dialog and removes newlines/tabs
messagesn=$(echo "${messages}" | nl -w1 | tr '\n' ' ' | tr '\t' ' ')

#Runs the tool dialog - choose message
chosenmessagen=$(bash -c "dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout \"Choose the message to filter for\" 0 0 0 ${messagesn[@]} 2>/dev/null")
chosenmessage=$(echo "${messages}" | sed -n ${chosenmessagen}p | sed -re "s/\b([0-9]+)\b\s*(.*)/\2/")

if [[ -z "$chosenmessage" ]]; then
	echo -e "Nichts gefunden!"
	exit 0
fi

#clear screen and show summary
clear
if [ $chosenhostn = '999' ]; then
        echo -e "Host: IP-Adresse\nMessage:\e[31m $chosenmessage\e[0m \n\n"
else
        echo -e "Host: ${chosenhost}\nMessage:\e[31m $chosenmessage\e[0m \n\n"
fi

#set alias as it is used multiple times
alias maincommand='grep -rHlP "^Host: $chosenhost" ${logpath} | xargs -I{} grep -rHlP "Total Score:\ \d+" {} | xargs -I{} grep -rlE "^Message.*$chosenmessage" {}'

maincommand
echo -e "\n"
maincommand | xargs -I{} grep -A1 '\-B\-\-' {} | grep -vE '^-' | sort | uniq
echo -e "\n"
maincommand | xargs -I{} grep -A1 '\-A\-\-' {} | awk '{print $4}' | sort | uniq | xargs -I{} host {}
echo -e "\n"
maincommand | xargs -I{} grep -oE "^Message.*$chosenmessage.*" {} | grep -oE "id\ \"[0-9]{6}\"" | sort | uniq
echo -e "\n"
maincommand | xargs -I{} grep -oE "^Message.*$chosenmessage.*" {} | sed "s/^Message.*Matched\ Data:\ //" | cut -d[ -f1 | sort | uniq

exit 0
