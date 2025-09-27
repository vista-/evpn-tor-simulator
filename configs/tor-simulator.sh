#!/bin/bash

ID=$(hostname | cut -d p -f2)

IPINDEX=$(( ID-1 ))
NEIGH_IPADDR=$(( IPINDEX*2 ))
IPADDR=$(( NEIGH_IPADDR + 1 ))

# Wait a bit for SR Linux nodes to start...
sleep 10

/evpn-tor-simulator --localaddrs 10.11.$((IPADDR / 256)).$((IPADDR % 256)),10.12.$((IPADDR / 256)).$((IPADDR % 256)) \
                    --neighbors 10.11.$((NEIGH_IPADDR / 256)).$((NEIGH_IPADDR % 256)),10.12.$((NEIGH_IPADDR / 256)).$((NEIGH_IPADDR % 256)) \
                    --neighbor-as ${NEIGH_AS} --id ${ID} --bridge-domains ${BD} --macs-per-bd ${MAC}