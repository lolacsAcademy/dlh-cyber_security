#!/bin/bash
ps -u "$1" -o user,pid,vsz,rss,tty,time,cmd | awk '$3 != 0 || $4 != 0'
