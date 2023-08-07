#!/bin/bash

echo Clearing flask servers...
killall flask
ps -ef | grep 'flask' | grep -v grep | awk '{print $2}' | xargs -r kill -9

echo done.