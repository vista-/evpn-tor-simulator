#!/bin/bash

ID=$(hostname | cut -d p -f2)

IPINDEX=$(( ID-1 ))
NEIGH_IPADDR=$(( IPINDEX*2 ))
IPADDR=$(( NEIGH_IPADDR + 1 ))

ip link set dev eth1 up
ip link set dev eth2 up
ip link add link eth1 name eth1.${ID} type vlan id ${ID}
ip link add link eth2 name eth2.${ID} type vlan id ${ID}
ip addr add 10.11.$((IPADDR/256)).$((IPADDR%256))/31 dev eth1.${ID}
ip addr add 10.12.$((IPADDR/256)).$((IPADDR%256))/31 dev eth2.${ID}
ip link set dev eth1.${ID} up
ip link set dev eth2.${ID} up
ip addr add 10.0.$((ID/256)).$((ID%256))/32 dev lo
ip ro add 1.1.1.1/32 via 10.11.0.${NEIGH_IPADDR}
ip ro add 2.2.2.2/32 via 10.12.0.${NEIGH_IPADDR}