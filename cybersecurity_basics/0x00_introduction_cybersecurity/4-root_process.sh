#!/bin/bash
ps -u "$1" -o user,pid,vsz,rss,tty,time,cmd | grep -v " 0 *0 "
