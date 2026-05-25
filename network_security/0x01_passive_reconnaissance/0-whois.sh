#!/bin/bash
whois $1 | awk -F': ' '/^Registrant |^Admin |^Tech /{if($1~/Street/) print $1", "$2; else if($1~/Ext/) print $1","$2; else print $1", "$2}' > $1.csv
