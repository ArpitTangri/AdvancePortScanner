#  Advanced Port Scanner (Java)

A mini-Nmap style port scanner written in **Java**.  

##  Features
- ✅ TCP connect scanning with timeout handling  
- ✅ Basic UDP scanning with packet send/receive  
- ✅ Simple service banner grabbing (HTTP, FTP, SSH, SMTP)  
- ✅ Object-Oriented Design using abstract classes  

##  Usage
```bash
javac AdvancePortScanner.java
java AdvancePortScanner <host> <startport> <endport> <type>

## Example
java AdvancePortScanner scanme.nmap.org 20 100 1

<type> = 1 for TCP, 2 for UDP
