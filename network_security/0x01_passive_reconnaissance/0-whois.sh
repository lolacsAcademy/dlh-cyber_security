#!/bin/bash
whois $1 | awk -F': ' '/^Registrant |^Admin |^Tech /{v=$2; if($1~/Street/) v=v" "; print $1", "v}' > $1.csv
