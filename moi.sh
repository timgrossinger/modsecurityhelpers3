#!/bin/bash

set -o pipefail

TIMESTAMPGREEN="\e[32m$(date "+%a %W %H:%M:%S:")\e[0m"
TIMESTAMPRED="\e[31m$(date "+%a %W %H:%M:%S:")\e[0m"

ignorestring="so-you-are-being-scanned"
logpath="/var/log/modsec_audit/www-data/$(date +%Y%m%d)"
tmpfile="/tmp/moi.tmp"
cachehosts="/tmp/moi.cache"
showscores=0
export=0

optstring=":hrp:i:l:o:s"

showhelp() {
  echo "--- $(basename $0) help ---"
  echo -e "\e[35m-h\e[0m show this help"
  echo -e "\e[35m-l PATH\e[0m set logpath (default: today)"
  echo -e "\e[35m-r\e[0m clear cache"
  echo -e "\e[35m-p n\e[0m filter for paranoia level (1–4)"
  echo -e "\e[35m-i STR\e[0m ignore logs matching string"
  echo -e "\e[35m-o FILE\e[0m output matched files to FILE"
  echo -e "\e[35m-s\e[0m show individual paranoia scores"
  exit 1
}

while getopts ${optstring} arg; do
  case ${arg} in
    h) showhelp ;;
    p)
      [[ ${OPTARG} =~ ^[1-4]$ ]] && searchstring="paranoia-level/${OPTARG}" || {
        echo -e "$TIMESTAMPRED ERROR! -p must be 1–4"
        showhelp
      }
      ;;
    i)
      [[ ${#OPTARG} -lt 5 ]] && { echo -e "$TIMESTAMPRED ERROR! Invalid -i"; showhelp; }
      ignorestring="${OPTARG}"
      ;;
    l)
      [[ ! -d ${OPTARG} ]] && { echo -e "$TIMESTAMPRED ERROR! Dir not found: ${OPTARG}"; showhelp; }
      logpath="${OPTARG}"
      ;;
    r)
      echo -e "$TIMESTAMPGREEN Clearing cache..."
      rm -f "${cachehosts}"
      ;;
    o)
      outputfile="${OPTARG}"
      touch "${outputfile}" || { echo -e "$TIMESTAMPRED Cannot create ${outputfile}"; showhelp; }
      export=1
      echo -e "$TIMESTAMPGREEN Exporting results to ${outputfile}"
      ;;
    s)
      showscores=1
      ;;
    ?) echo -e "$TIMESTAMPRED Unknown option: -${OPTARG}"; showhelp ;;
  esac
done

which dialog > /dev/null || { echo -e "$TIMESTAMPRED Please install 'dialog'"; exit 1; }

if [ ! -s "${cachehosts}" ]; then
  grep -rHlP "${searchstring}" "${logpath}" 2>/dev/null | \
    xargs -r grep -HLE "${ignorestring}" | \
    xargs -r grep -hE '^Host' | grep -vE '[0-9]' | \
    sed 's/.* //' | sort -u > "${cachehosts}"
fi

hosts=$(cat "${cachehosts}")
hostsn=$(echo "${hosts}" | nl -w1 | tr '\n' ' ')
chosenhostn=$(dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout 'Choose the host to filter for' 0 0 0 ${hostsn} 999 "IP address" 2>/dev/null)

[[ "${chosenhostn}" == "999" ]] && chosenhost='\d{1,3}(\.\d{1,3}){3}' || chosenhost=$(echo "${hosts}" | sed -n ${chosenhostn}p)

messages=$(grep -rHlP "^Host: ${chosenhost}" "${logpath}" 2>/dev/null | \
  xargs -r grep -HLE "${ignorestring}" | \
  xargs -r grep -rHlP "${searchstring}" | \
  xargs -r grep -hPo '\[msg\s+"[^"]+"\]' | \
  sed -e 's/\[msg "//' -e 's/"\]//' | sort | uniq -c | sort -rh | \
  sed 's/^ *//' | sed -r 's/^([0-9]+)\s+(.*)$/\1 \2/' | sed 's/$/"/' | sed 's/^/"/')

messagesn=$(echo "${messages}" | nl -w1 | tr '\n' ' ' | tr '\t' ' ')
chosenmessagen=$(bash -c "dialog --backtitle 'moi - a modsecurityhelpers tool' --menu --stdout \"Choose the message to filter for\" 0 0 0 ${messagesn[@]} 2>/dev/null")
chosenmessage=$(echo "${messages}" | sed -n "${chosenmessagen}p" | sed -r 's/^"([0-9]+)\s+//' | sed 's/"$//')

[[ -z "${chosenmessage}" ]] && { echo "Nothing found!"; exit 1; }

clear
echo -e "Host: ${chosenhost}\nMessage:\e[31m ${chosenmessage} \e[0m\n"

grep -rHlP "^Host: ${chosenhost}" "${logpath}" | \
  xargs -r grep -HLE "${ignorestring}" | \
  xargs -r grep -rHlP "${searchstring}" | \
  xargs -r grep -lP "${chosenmessage}" > "${tmpfile}"

if [[ "${showscores}" -eq 0 ]]; then
  cat "${tmpfile}"
else
  cat "${tmpfile}" | xargs -I{} bash -c "echo {}; grep -Po 'scores.*paralevel4:[0-9]*' {} | head -n1"
fi

echo -e "\n"

[[ "${export}" -eq 1 ]] && {
  cat "${tmpfile}" > "${outputfile}"
  echo -e "-o was set. Results exported to: ${outputfile}\n"
}

cat "${tmpfile}" | xargs -I{} grep -A1 '\-B\-\-' {} | grep -vE '^-' | sort | uniq
echo -e "\n"

# IP display
realip=$(find "${logpath}" -type f | head -n100 | xargs -r grep -cE '^X-Real-IP')
if [[ ${realip} -gt 0 ]]; then
  cat "${tmpfile}" | xargs -I{} grep -E '^X-Real-IP' {} | awk '{print $2}' | sort | uniq | \
    xargs -I{} bash -c 'echo -e "\e[31mIP address:\e[0m\n{}\n\e[31mPTR-Record:\e[0m" ; host {} ; echo ""'
else
  cat "${tmpfile}" | xargs -I{} grep -A1 '\-A\-\-' {} | awk '{print $4}' | sort | uniq | \
    xargs -I{} bash -c 'echo -e "\e[31mIP address\e[0m:\n{}\n\e[31mPTR-Record:\e[0m" ; host {} ; echo ""'
fi

echo -e "\nRule IDs and Phases:\n"
cat "${tmpfile}" | xargs -I{} grep -Po '\[id "\d+"\]|\(phase \d\)' {} | sort | uniq

echo -e "\nFull Rule Messages:\n"
cat "${tmpfile}" | xargs -I{} awk '/--H--/,/--[A-Z]--/ {print}' | grep -v "^--" | sort | uniq

rm "${tmpfile}"
exit 0
