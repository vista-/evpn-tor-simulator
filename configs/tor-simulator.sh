#!/bin/bash

ID=$(hostname | cut -d p -f2)

IPINDEX=$(( ID-1 ))
NEIGH_IPADDR=$(( IPINDEX*2 ))
LOCAL_IPADDR=$(( NEIGH_IPADDR + 1 ))

SPINEINDICES=${SPINEINDICES:-"11,12"}
LOCAL_ADDRS=$(IFS=,; for i in $SPINEINDICES; do echo -n "10.${i}.$((LOCAL_IPADDR / 256)).$((LOCAL_IPADDR % 256)),"; done | sed 's/,$//')
NEIGH_ADDRS=$(IFS=,; for j in $SPINEINDICES; do echo -n "10.${j}.$((NEIGH_IPADDR / 256)).$((NEIGH_IPADDR % 256)),"; done | sed 's/,$//')

# Wait a bit for SR Linux nodes to start...
sleep 10

/evpn-tor-simulator --localaddrs ${LOCAL_ADDRS} --neighbors ${NEIGH_ADDRS}  --neighbor-as ${NEIGH_AS} \
                    --rrs ${RRs:-"1.1.1.1,2.2.2.2"} --rr-as ${RR_AS:-65500} \
                    --id ${ID} --bridge-domains ${BD} --macs-per-bd ${MAC}