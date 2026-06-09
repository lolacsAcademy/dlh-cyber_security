# 0x04 Content Discovery

## Objective
Use Gobuster `dir` mode to discover hidden directories and `.php` endpoints.

## Target
http://web0x04.hbtn

## Tools Used
- gobuster
- Kali Linux

## Wordlists Used
- gobuster-common.txt
- WP_Word_list.txt

## Method
- Ran Gobuster in dir mode
- Fuzzed directories and PHP endpoints using `-x php`
- Analyzed HTTP status codes (200, 301, 302, 403)

## Findings
- Discovered hidden directories
- Identified WordPress-related endpoints
- Extracted flag from HTTP response header

## Flag File
4-flag.txt
