# report-netfilter-test
bob 13 - report netfilter test

# how to run?

1. setup to iptable policy 
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0

2. install dependency
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev

3. build soucre file
gcc -o netfilter-test netfilter-test.c -lnetfilter_queue


4. run binary
syntax : netfilter-test <host>
(only http protocol host)

5. clean
sudo iptable -F
