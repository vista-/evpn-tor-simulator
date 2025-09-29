#!/bin/bash

ID=$(hostname | cut -d p -f2)

IPINDEX=$(( ID - 1 ))
NEIGH_IPADDR=$(( IPINDEX * 2 ))
LOCAL_IPADDR=$(( NEIGH_IPADDR + 1 ))

RRs=${RRs:-"1.1.1.1,2.2.2.2"}
RR_ARRAY=($(echo "$RRs" | tr ',' '\n'))

SPINEINDICES=${SPINEINDICES:-"11,12"}
SPINEINDEX_ARRAY=($(echo "$SPINEINDICES" | tr ',' '\n'))

ip link set dev eth1 up
ip link set dev eth2 up
ip link add link eth1 name eth1.${ID} type vlan id ${ID}
ip link add link eth2 name eth2.${ID} type vlan id ${ID}
for i in $(seq 0 1); do
  ip addr add 10.${SPINEINDEX_ARRAY[$((i))]}.$((LOCAL_IPADDR / 256)).$((LOCAL_IPADDR % 256))/31 dev eth$((i + 1)).${ID}
done
ip link set dev eth1.${ID} up
ip link set dev eth2.${ID} up
ip addr add 10.0.$((ID/256)).$((ID%256))/32 dev lo

for j in $(seq 0 1); do
  ip ro add ${RR_ARRAY[${j}]}/32 via 10.${SPINEINDEX_ARRAY[${j}]}.$((NEIGH_IPADDR / 256)).$((NEIGH_IPADDR % 256))
done