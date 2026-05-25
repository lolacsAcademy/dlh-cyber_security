#!/bin/bash
subfinder -silent -d $1|tee >(while read s;do echo $s,$(dig +short $s|head -n1);done>$1.txt)
