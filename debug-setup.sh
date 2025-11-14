sudo ip addr add 10.11.0.1/31 dev debug-link
sudo ip addr add 82.0.0.1/32 dev lo
sudo ip route add 1.1.1.1/32 via 10.11.0.0

echo "Now start debugging from VS Code"
echo
echo "In SR Linux, to view BGP debug logs: "
echo "show system logging buffer bgp-debug"
