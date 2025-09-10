#  Advanced Port Scanner (Java)

A mini-Nmap style port scanner written in **Java**.  

##  Features
 *  - TCP connect scanning
 *  - UDP scanning (basic)
 *  - Service banner grabbing (HTTP, FTP, SSH, SMTP)
 *  - OS detection (basic RTT method)
 *  - Threaded scanning for speed
 *  - Results logged to file

##  Usage
```bash
javac AdvancePortScanner.java
java AdvancePortScanner <host> <startport> <endport> <type>

## Example
java AdvancePortScanner scanme.nmap.org 20 100 1

<type> = 1 for TCP, 2 for UDP
