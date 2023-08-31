# ossec-teams
Ossec Action Response to send alerts to Microsoft Teams via Incoming Webhook

# Usage
Place ossec-teams.sh in the active-response/bin folder. Don't forget to fill the SITE url with the incoming webhook URL.

# Changes to original ossec-slack
- Modify to send alert according to Microsoft Teams Incomong Webhook format with Adaptive Card.
- Modify on POST using wget or curl. Needs Content-Type: application/json for it to work.

# Credits
Credits given to ossec-hids active response: ossec-slack. This is a modification from the original ossec-slack to work with Microsoft Teams. 
