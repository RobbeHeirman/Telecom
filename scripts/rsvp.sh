#!/bin/bash

# Set test to false when using the script in the VM with the complete solution
TEST=true


SRC="SRC 192.168.10.1, PORT 7"
DST="DST 192.168.11.1, PORT 2222"
ID="ID 1"


if [ "$TEST" = true ]; then
	HOST1_PORT="10000";	HOST1_NAME="host1"
	ROUT1_PORT="10000";	ROUT1_NAME="router1"
	ROUT2_PORT="10000";	ROUT2_NAME="router2"
	HOST2_PORT="10000";	HOST2_NAME="host2"
else
	HOST1_PORT="10001";	HOST1_NAME="host1/rsvpHost"
	ROUT1_PORT="10002";	ROUT1_NAME="router1/rsvpRouter"
	ROUT2_PORT="10003";	ROUT2_NAME="router2/rsvpRouter"
	HOST2_PORT="10004";	HOST2_NAME="host2/rsvpHost"
fi


# Call with following arguments:
#    element_name			one of:		HOST1 | ROUT1 | ROUT2 | HOST2
#    handler_name			example:	session
#    handler_arguments		example:	1, 1.1.1.1, 1

function rsvp {
	port=$1_PORT
	name=$1_NAME

	echo
	echo "write ${!name}.$2 ${@:3}"
	(echo "write ${!name}.$2 ${@:3}"; sleep 0.5) | telnet localhost ${!port} #>/dev/null
}


rsvp HOST1 session $ID, $DST
rsvp HOST2 session $ID, $DST
rsvp HOST1 sender $ID, $SRC
rsvp HOST2 reserve $ID, CONF true
rsvp HOST2 release $ID
#rsvp HOST1 release $ID

