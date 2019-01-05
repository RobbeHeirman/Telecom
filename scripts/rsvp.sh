#!/bin/bash

# If the first argument is true, the script will assume it's running in the VM in ~/click-reference/solution
#  and that the two start_click.sh scripts need to be started. Otherwise a click process should be running
#  already that can be connected with on port 10000. If no arguments are provided, the script assumes it
#  not running in the VM
if [[ $# -eq 1 && $1 == "VM" ]]; then
	VM=true
else
	VM=false
fi


# Location of the start_click.sh files relative to ~/click-reference/solution/rsvp.sh
REF="./start_click.sh"
OWN="../../click/scripts/start_click.sh"

# Default addresses of the hosts in the reference implementation
SRC="SRC 192.168.10.1, PORT 7"
DST="DST 192.168.11.1, PORT 2222"
ID="ID 1"


if [ $VM = false ]; then
	# Values as used in test.click
	HOST1_PORT="10000";	HOST1_NAME="host1"
	ROUT1_PORT="10000";	ROUT1_NAME="router1"
	ROUT2_PORT="10000";	ROUT2_NAME="router2"
	HOST2_PORT="10000";	HOST2_NAME="host2"

	echo TEST 2
else
	# Values as used in the reference implementation
	HOST1_PORT="10001";	HOST1_NAME="host1/rsvpHost"
	ROUT1_PORT="10002";	ROUT1_NAME="router1/rsvpRouter"
	ROUT2_PORT="10003";	ROUT2_NAME="router2/rsvpRouter"
	HOST2_PORT="10004";	HOST2_NAME="host2/rsvpHost"

	echo TEST 1
fi


# Function that calls a click handler (example: rsvp HOST1 session ID 1, DST 1.1.1.1, PORT 1)
function rsvp {
	# Temporary variables to hold other variables' names
	port=$1_PORT
	name=$1_NAME

	# Print the click handler that is being called and then actually call the handler
	echo "write ${!name}.$2 ${@:3}"
	(echo "write ${!name}.$2 ${@:3}"; sleep 0.5) | telnet localhost ${!port} >/dev/null 2>/dev/null
}


# Run both start_click.sh scripts, make sure these have the right lines commented out
if [ $VM = true ]; then
	$REF &
	$OWN &
	sleep 0.1 # Give click some time to start
fi


# The click handlers to be used
################################################################################
rsvp HOST1 session $ID, $DST
rsvp HOST2 session $ID, $DST
rsvp HOST1 sender $ID, $SRC
sleep 1.0
rsvp HOST2 reserve $ID, CONF true
################################################################################


# Stop $REF and $OWN by killing all click processes
if [ $VM = true ]; then
	read -p "" 
	pkill click
fi
