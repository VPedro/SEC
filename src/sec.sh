#!/bin/bash

gnome-terminal -e "bash -c \"javac pt/ist/sec/proj/*.java;\""
#gnome-terminal -e "bash -c \"echo ; exec bash\""
sleep 0.5
gnome-terminal -e "bash -c \"java pt.ist.sec.proj.Server 1; exec bash\""
sleep 0.5
gnome-terminal -e "bash -c \"java pt.ist.sec.proj.Server 2; exec bash\""
sleep 0.5
gnome-terminal -e "bash -c \"java pt.ist.sec.proj.Server 3; exec bash\""
sleep 0.5
gnome-terminal -e "bash -c \"java pt.ist.sec.proj.Register; exec bash\""

read -p "Press any key to close the servers and register"
var=`ps aux | grep "bash -c"`
for word in "$var"
do
	echo "$word" | cut -f6 -d' ' | while IFS= read -r line ; do
							    		echo $line; kill $line 2>/dev/null
									done
done