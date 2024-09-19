
# Report: Netfilter Test
**Bob 13 - Report Netfilter Test**

## How to Run

### 1. Setup iptables Policy

```bash
sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```

### 2. Install Dependency

```bash
sudo apt-get update
sudo apt-get install libnetfilter-queue-dev
```

### 3. Build Source File

```bash
gcc -o netfilter-test netfilter-test.c -lnetfilter_queue
```

### 4. Run Binary

```bash
syntax: netfilter-test <host>
(only HTTP protocol host)
```

### 5. Clean

```bash
sudo iptables -F
```

