#!/bin/bash

# Date:   2021-09-20
# Author: Juergen Mang <juergen.mang@axians.de>

if [ "$#" -eq 0 ]
then
    echo "Usage: $0 <tcpdump filter>";
    echo ""
    echo "This script enables (SSL) debug options, runs tcpdump and creates a pre master secret file."
    echo "Open the .dmp file in Wireshark and use the .pms file to decrypt ssl."
    exit 1;
fi

#Try to find the gensecrets-tls.pl script
GENSECRET_LOCATIONS="/shared/axians/scripts/gensecrets-tls.pl ./gensecrets-tls.pl /root/gensecrets-tls.pl /home/admin/gensecrets-tls.pl"
GENSECRETS=""

for L in $GENSECRET_LOCATIONS
do
    [ -x "$L" ] && { GENSECRETS="$L"; break; }
done

[ "$GENSECRETS" = "" ] && { echo "gensecrets-tls.pl not found"; exit 1; }

#Create tmp directory
TMPDIR=$(mktemp -d /var/tmp/dump.XXXXXXXXXX)

#Enable debug options
echo "Enabling rstcause logging"
tmsh modify /sys db tm.rstcause.log value enable
tmsh modify /sys db tm.rstcause.pkt value enable

echo "Enabling f5 sslprovider"
tmsh modify sys db tcpdump.sslprovider value enable

echo "Enabling ssl debug"
tmsh modify /sys db log.ssl.level value Debug
echo "Starting tcpdump, press Ctrl+C to quit"

#Run tcpdump
tcpdump -nni 0.0:nnnp -s0 --f5 ssl:v -vvv -w "$TMPDIR/dump.pcap" $@

#Disable debug options
echo "Disabling rstcause logging"
tmsh modify /sys db tm.rstcause.log value disable
tmsh modify /sys db tm.rstcause.pkt value disable

echo "Disabling f5 sslprovider"
tmsh modify sys db tcpdump.sslprovider value disable

echo "Disabling ssl debug"
tmsh modify /sys db log.ssl.level value Warning

#Create pre master secret file
echo "Generating pre master secret file"
"$GENSECRETS" "$TMPDIR/dump.pcap" > "$TMPDIR/dump.pms"

echo "Dump directory: $TMPDIR"

exit 0;
