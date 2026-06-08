#!/bin/bash
curl -s -c jar2.txt --data "username=yosri&password=yosri" http://web0x01.hbtn/a3/xss_stored/login
cat jar2.txt
curl -s -b jar2.txt http://web0x01.hbtn/a3/xss_stored/profile/
