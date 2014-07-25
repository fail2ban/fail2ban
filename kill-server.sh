#!/bin/bash
kill `ps ax|grep fail2ban|grep -v grep|awk '{print $1}'`
