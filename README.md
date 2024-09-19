# report-netfilter-test
bob 13 - report netfilter test

# how to run?

1. setup to iptable policy <br/> 
sudo iptables -F<br/> 
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0<br/> 
sudo iptables -A INPUT -j NFQUEUE --queue-num 0<br/> 
<br/> 
2. install dependency<br/> 
sudo apt-get update<br/> 
sudo apt-get install libnetfilter-queue-dev<br/> 
<br/> 
3. build soucre file<br/> 
gcc -o netfilter-test netfilter-test.c -lnetfilter_queue<br/> 
<br/> 

4. run binary<br/> 
syntax : netfilter-test <host><br/> 
(only http protocol host)<br/> 
<br/> 
5. clean<br/> 
sudo iptable -F<br/> 
