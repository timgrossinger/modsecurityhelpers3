#!/bin/bash

#uncomment to debug
#set -x

#activate pipefail
set -o pipefail

#set ignorestring
#maybe to exclude logs caused by a scanner like burpsuite, ZAP,...
#use IP addresses or (parts of) User-Agent
#this is used as a regular expresion, so separate with pipes: |
if [[ -z "$ignorestring" ]]; then
  ignorestring="so-you-are-being-scanned"
fi
if [[ ${#ignorestring} -lt 3 ]]; then
  echo "ignorestring too short"
  exit 1
fi

searchstring="Total Score:\ \d+"

#sets path of temporary files
#don't touch, if unsure
tmpfile="/tmp/moi.tmp"
cachehosts="/tmp/moi.cache"

#Define Path where the logs are
if [[ -z "$logpath" ]]; then
  logpath=/var/log/modsec_audit/www-data/$(date +%Y%m%d)
fi

#show help if wanted
for i in "$@"; do
  if [[ $i = "-h" || $i = "--help" ]]; then
          echo "--- moi help ---"
          echo " -h / --help: show this help"
          echo " -r / --clear-cache: clears cache"
          exit 0
  fi
done

#clears cache if wanted
for i in "$@"; do
  if [[ $i = "-r" || $i = "--clear-cache" ]]; then
	  echo "Clearing cache..."
	  echo "Deleting ${cachehosts} 0%"
          rm ${cachehosts}
	  echo "Deleting ${cachehosts} 100%"
	  echo "Cache cleared."
	  echo "New cache is being generated."
	  echo "Do not interrupt!"
  fi
done

#test: is dialog installed?
if ! which dialog > /dev/null; then
	echo --- ERROR ---
	echo dialog not found
	echo Please install dialog with \"sudo apt install dialog\"
	echo --- ERROR ---
	exit 1
fi

if which figlet > /dev/null; then
figlet -f script moi
echo -e "\n...is loading. Please wait!"
else
echo " x"
echo " x        xx             xxxx xxx"
echo " x      xx  xx         xx        x"
echo " x    xx     xx       x           x"
echo "  x   x        x     x            x"
echo "  x  x         x    x              x"
echo "  x x          x    x              x                 "
echo "  x x           x  x               x                x"
echo "  x x            x x               x                 "
echo "   xx            x x               x"
echo "   xx             x               xx"
echo "   xx            xx               x"
echo "   xx            xx              x         xxxx     x"
echo "    x            xx             x      xxxxx   x    x"
echo "    x            x            xx     xxxx      x    x"
echo "    x            x            x      xx        x    x"
echo "    x            x           xx     x          x    x"
echo "    x                        x      xx        x     x"
echo "    x                        xx      xx     xx      xx    x"
echo "    x                          xx     xxxxxx         xxxxx"
echo "    x"
echo "          moi is loading. Please wait!"
fi

#create cachehosts tempfile with the hosts (can save lots of time)
if [ ! -s ${cachehosts} ]; then
  grep -rHlP "${searchstring}" ${logpath} | \
	  xargs -I{} grep -HLE "${ignorestring}" {} | \
	  xargs -I{} grep -hE '^Host' {} | \
	  grep -vE [0-9] | sort | uniq | \
	  sed 's/.*\ //' > ${cachehosts}
fi

#Reads host entries from Request Header from the logs
hosts=$(cat ${cachehosts})

#Check if X-Real-IP Header is present (specific Webserver/Reverse Proxy configuration)
let realip=$(find ${logpath} -type f | \
	head -n100 | \
	xargs -I{} grep -E '^X-Real-IP' {} | \
	wc -l 2>/dev/null)

#Adds numbers for usage with the tool dialog and removes newlines
hostsn=$(echo "${hosts}" | nl -w1 | tr '\n' ' ')

#Runs the tool dialog - choose host header to grep for (or IP address)
chosenhostn=$(dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout 'Choose the host to filter for' 0 0 0 ${hostsn} 999 "IP address" 2>/dev/null)

#set variable chosenhost to regex of IP address when IP address has been chosen
if [ $chosenhostn = '999' ]; then
	chosenhost='\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
else
	chosenhost=$(echo "${hosts}" | sed -n ${chosenhostn}p)
fi

#Reads messages & number of occurence
messages=`grep -rHlP "^Host: $chosenhost" ${logpath} | \
	xargs -I{} grep -HLE "${ignorestring}" {} | \
	xargs -I{} grep -rHlP "${searchstring}" {} | \
	xargs -I{} grep -hP '^Message.*\[msg.+?\]' {} | \
	grep -hPo '\[msg.+?\]' | sort | uniq -c | \
	sed 's/^ *//' | sed -e 's/(/./g' | sed -e 's/)/./g' | sort -rh | \
	grep -vE '(In|Out)bound\ Anomaly' | \
	sed -re 's/\b([0-9]+)\b.*\[msg\ \"(.*)\"\]$/\"\1 \2\"/'`

#Adds numbers for usage with the tool dialog and removes newlines/tabs
messagesn=$(echo "${messages}" | nl -w1 | tr '\n' ' ' | tr '\t' ' ')

#Runs the tool dialog - choose message
chosenmessagen=$(bash -c "dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout \"Choose the message to filter for\" 0 0 0 ${messagesn[@]} 2>/dev/null")
chosenmessage=$(echo "${messages}" | sed -n ${chosenmessagen}p | sed -re "s/\b([0-9]+)\b\s*(.*)/\2/")

if [[ -z "$chosenmessage" ]]; then
	echo -e "Nothing found! Sorry!"
	exit 1
fi

#clear screen and show results
clear
if [ $chosenhostn = '999' ]; then
        echo -e "Host: IP address\nMessage:\e[31m $chosenmessage\e[0m \n\n"
else
        echo -e "Host: ${chosenhost}\nMessage:\e[31m $chosenmessage\e[0m \n\n"
fi

grep -rHlP "^Host: $chosenhost" ${logpath} | \
	xargs -I{} grep -HLE "${ignorestring}" {} | \
	xargs -I{} grep -rHlP "${searchstring}" {} | \
	xargs -I{} grep -rlE "^Message.*$chosenmessage" {} > ${tmpfile}

cat ${tmpfile}
echo -e "\n"
cat ${tmpfile} | xargs -I{} grep -A1 '\-B\-\-' {} | grep -vE '^-' | sort | uniq
echo -e "\n"
if [ ${realip} -gt 0 ]; then
	cat ${tmpfile} | xargs -I{} grep -E '^X-Real-IP' {} | awk '{print $2}' | sort | uniq | \
		xargs -I{} bash -c 'echo -e "\e[31mIP address:\e[0m\n{}\n\e[31mPTR-Record:\e[0m" ; host {} ; echo -e ""'
else
        cat ${tmpfile} | xargs -I{} grep -A1 '\-A\-\-' {} | awk '{print $4}' | sort | uniq | \
		xargs -I{} bash -c 'echo -e "\e[31mIP address\e[0m:\n{}\n\e[31mPTR-Record:\e[0m" ; host {} ; echo -e ""'
fi
echo -e "\n"
cat ${tmpfile} | xargs -I{} grep -oE "^Message.*$chosenmessage.*" {} | grep -oE "id\ \"[0-9]{6}\"" | sort | uniq
echo -e "\n"
cat ${tmpfile} | xargs -I{} grep -oE "^Message.*$chosenmessage.*" {} | sed -re 's/\[file.*$/\n\n/g' | sort | uniq | sed 's/$/\n/'

#clean up
rm ${tmpfile}
exit 0
