#!/bin/bash
find / -type d -perm -o+w -exec echo {} \; -exec chmod o-w {} \;
