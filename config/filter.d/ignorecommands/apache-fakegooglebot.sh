#!/bin/sh
# Based on: https://isc.sans.edu/forums/diary/When+Google+isnt+Google/15968/

if [ "$#" -ne 1 ]; then
    echo "Unexpected number of arguments: $#"
    exit 1
else
    b="$1"
    h=$(host ${b})
    if echo ${h} | grep -e ' crawl-.*\.googlebot\.com\.$'; then
      h=$(echo ${h} | cut -f5 -d' ')
      n=$(host ${h} | cut -f4 -d' ')
      if [ "${n}" = "${b}" ] ; then
        exit 0
      else
        exit 1
      fi
    else
      exit 1
    fi
fi
