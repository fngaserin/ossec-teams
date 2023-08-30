#!/bin/sh
# Send alert to Microsoft Teams Incoming Webhook
# Path: /var/ossec/active-response/bin/ossec-teams.sh
# Authors: Felix Ngaserin (fngaserin)
# Last modified: Aug 30, 2023
#
# Sample config (Edit /var/ossec/etc/ossec.conf):
#
#  <command>
#     <name>ossec-teams</name>
#     <executable>ossec-teams.sh</executable>
#     <timeout_allowed>no</timeout_allowed>
#     <expect></expect>
#  </command>
#
#  <active-response>
#     <command>ossec-teams</command>
#     <location>local</location>
#     <level>7</level>
#  </active-response>


# Change these values!
# SITE is the URL provided by the Microsoft Teams Incoming WebHook, something like:
# https://xxxxxxxxxxxxxx.webhook.office.com/webhookb2/xxxxxxxxxxx"

SITE=""
SOURCE="ossec2teams"


# Checking user arguments
if [ "x$1" = "xdelete" ]; then
    exit 0;
fi
ALERTID=$4
RULEID=$5
LOCAL=`dirname $0`;

# Logging
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log
ALERTTITLE=`grep -A 1 "$ALERTID" ${PWD}/../logs/alerts/alerts.log | tail -1`
ALERTTEXT=`grep -A 10 "$ALERTID" ${PWD}/../logs/alerts/alerts.log | grep -v "Src IP: " | grep -v "User: " | grep "Rule: " -A 4 | sed '/^$/Q' | cut -c -139 | sed 's/\"//g'`

LEVEL=`echo "${ALERTTEXT}" | head -1 | grep "(level [0-9]*)" | sed 's/^.*(level \([0-9]*\)).*$/\1/'`
COLOR="default"
if [ "${LEVEL}" ]
then
  [ "${LEVEL}" -ge 4 ] && COLOR="good"
  [ "${LEVEL}" -ge 7 ] && COLOR="warning"
  [ "${LEVEL}" -ge 12 ] && COLOR="attention"
fi

PAYLOAD='{ 
    "type": "message", 
    "attachments": [ 
        { 
            "contentType":"application/vnd.microsoft.card.adaptive", 
            "contentUrl":null, 
            "content": { 
                "$schema":"http://adaptivecards.io/schemas/adaptive-card.json", 
                "type":"AdaptiveCard", 
                "version":"1.5", 
                "body": [ 
                    { 
                        "type": "TextBlock", 
                        "size":"medium", 
                        "weight":"bolder", 
                        "text": "'"${ALERTTITLE}"'", 
                        "style":"heading", 
                        "wrap":true 
                    }, 
                    { 
                        "type": "TextBlock", 
                        "text": "'"${ALERTTEXT}"'", 
                        "color": "'"${COLOR}"'", 
                        "wrap":true 
                    } 
                ] 
            } 
        } 
    ] 
}'


ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        wget --keep-session-cookies --header='Content-Type:application/json' --post-data="${PAYLOAD}" ${SITE} 2>>${PWD}/../logs/active-responses.log
        exit 0;
    fi
else
    curl -s -H 'Content-Type: application/json' -d "$PAYLOAD" "$SITE" 2>>${PWD}/../logs/active-responses.log
    exit 0;
fi

echo "`date` $0: Unable to find curl or wget." >> ${PWD}/../logs/active-responses.log
