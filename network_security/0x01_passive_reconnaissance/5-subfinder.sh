#!/bin/bash
subfinder -silent -d $1 -nW -oI|cut -d',' -f1,2|tee $1.txt
