ip link add bridge1 type bridge
ip link add bridge2 type bridge
ip link set dev bridge1 up
ip link set dev bridge2 up

CGO_ENABLED=0 go build .

## NOTE: MUST USE containerlab BUILT FROM BRANCH feature/idiv-template UNTIL CONTAINERLAB 0.70.3 IS RELEASED
clab destroy && clab deploy -c
