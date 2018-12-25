#!/bin/bash

# Initialise session in host 1 & 2
(echo "write host1/rsvpHost.session ID 1, DST 192.168.11.1, PORT 2222"; sleep 0.5) | telnet localhost 10001 >/dev/null
(echo "write host2/rsvpHost.session ID 1, DST 192.168.11.1, PORT 2222"; sleep 0.5) | telnet localhost 10004 >/dev/null

# Start sending PATH messages from host 1
(echo "write host1/rsvpHost.sender ID 1, SRC 192.168.10.1, PORT 7"; sleep 0.5) | telnet localhost 10001 >/dev/null

# Confirm the reservation in host 2
(echo "write host2/rsvpHost.reserve ID 1"; sleep 0.5) | telnet localhost 10004 >/dev/null

# Wait a short while and release the RSVP connection
sleep 5
# RESV TEAR
(echo "write host2/rsvpHost.release ID 1"; sleep 0.5) | telnet localhost 10004 >/dev/null
# PATH TEAR
#(echo "write host1/rsvpHost.release ID 1"; sleep 0.5) | telnet localhost 10001 >/dev/null

