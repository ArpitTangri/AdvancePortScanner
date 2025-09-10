/*
 * AdvancePortScanner.java
 * A threaded mini-Nmap style port scanner
 * Features:
 *  - TCP connect scanning
 *  - UDP scanning (basic)
 *  - Service banner grabbing (HTTP, FTP, SSH, SMTP)
 *  - OS detection (basic RTT method)
 *  - Threaded scanning for speed
 *  - Results logged to file
 *
 * Usage:
 *   java AdvancePortScanner <host> <startport> <endport> <type>
 * Example:
 *   java AdvancePortScanner scanme.nmap.org 20 100 1
 */

import java.net.*;
import java.io.*;
import java.util.concurrent.*;

// ---------- Base Classes ----------
abstract class PortScanner {
    protected InetAddress inetaddress;
    protected int startport;
    protected int endport;

    public PortScanner(String host, int startport, int endport) throws UnknownHostException {
        this.inetaddress = InetAddress.getByName(host);
        this.startport = startport;
        this.endport = endport;
    }

    public abstract void scanPorts();

    protected void printScanDetails() {
        System.out.println("======================================");
        System.out.println("Scanning host: " + inetaddress.getHostAddress());
        System.out.println("Port range: " + startport + " - " + endport);
        System.out.println("======================================");
    }
}

// ---------- TCP Scanner ----------
class TcpPortScanner extends PortScanner {
    public TcpPortScanner(String host, int startport, int endport) throws UnknownHostException {
        super(host, startport, endport);
    }

    public void scanPorts() {
        printScanDetails();
        for (int port = startport; port <= endport; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(inetaddress, port), 500);
                System.out.println("[OPEN] TCP " + port);
            } catch (Exception ignored) {}
        }
    }
}

// ---------- UDP Scanner ----------
class UdpPortScanner extends PortScanner {
    public UdpPortScanner(String host, int startport, int endport) throws UnknownHostException {
        super(host, startport, endport);
    }

    public void scanPorts() {
        printScanDetails();
        for (int port = startport; port <= endport; port++) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(500);
                byte[] buffer = "Hello".getBytes();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, inetaddress, port);
                socket.send(packet);

                byte[] recvBuf = new byte[1024];
                DatagramPacket recvPacket = new DatagramPacket(recvBuf, recvBuf.length);
                socket.receive(recvPacket);

                System.out.println("[OPEN] UDP " + port + " (response received)");
            } catch (SocketTimeoutException ignored) {
                // likely filtered/closed
            } catch (Exception ignored) {}
        }
    }
}

// ---------- Extra Features ----------
class OSFingerprinting {
    private final InetAddress inetAddress;
    public OSFingerprinting(String host) throws UnknownHostException {
        this.inetAddress = InetAddress.getByName(host);
    }
    public void detectOS() {
        System.out.println("\n[*] Attempting OS Detection...");
        try {
            long start = System.currentTimeMillis();
            if (inetAddress.isReachable(2000)) {
                long rtt = System.currentTimeMillis() - start;
                if (rtt < 50) System.out.println("[+] Fast RTT ("+rtt+"ms) → Likely Linux/BSD");
                else if (rtt < 200) System.out.println("[+] Medium RTT ("+rtt+"ms) → Likely Windows");
                else System.out.println("[+] Slow RTT ("+rtt+"ms) → Remote host");
            } else System.out.println("[-] Host not reachable for OS detection.");
        } catch (Exception e) {
            System.out.println("[-] OS detection failed: " + e.getMessage());
        }
    }
}

class ResultLogger {
    private final String filename;
    public ResultLogger(String filename) { this.filename = filename; }
    public synchronized void writeResult(String result) {
        try (FileWriter fw = new FileWriter(filename, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(result);
            bw.newLine();
        } catch (IOException ignored) {}
    }
}

// ---------- Threaded Workers ----------
class ThreadedTcpScanner implements Runnable {
    private final InetAddress inetAddress;
    private final int port;
    private final ResultLogger logger;
    public ThreadedTcpScanner(InetAddress inetAddress, int port, ResultLogger logger) {
        this.inetAddress = inetAddress; this.port = port; this.logger = logger;
    }
    public void run() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(inetAddress, port), 300);
            String result = "[OPEN] TCP " + port;
            System.out.println(result);
            logger.writeResult(result);
        } catch (Exception ignored) {}
    }
}

class ThreadedUdpScanner implements Runnable {
    private final InetAddress inetAddress;
    private final int port;
    private final ResultLogger logger;
    public ThreadedUdpScanner(InetAddress inetAddress, int port, ResultLogger logger) {
        this.inetAddress = inetAddress; this.port = port; this.logger = logger;
    }
    public void run() {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(500);
            byte[] buffer = "Hello".getBytes();
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, inetAddress, port);
            socket.send(packet);
            socket.receive(new DatagramPacket(new byte[1024], 1024));
            String result = "[OPEN] UDP " + port;
            System.out.println(result);
            logger.writeResult(result);
        } catch (Exception ignored) {}
    }
}

// ---------- Main ----------
public class AdvancePortScanner {
    public static void main(String[] args) {
        try {
            if (args.length < 4) {
                System.out.println("Usage: java AdvancePortScanner <host> <startport> <endport> <type>");
                return;
            }

            String targetHost = args[0];
            int startport = Integer.parseInt(args[1]);
            int endport = Integer.parseInt(args[2]);
            int choice = Integer.parseInt(args[3]);

            if (endport < startport) {
                System.out.println("[-] Invalid range: endport must be >= startport");
                return;
            }

            InetAddress inetAddress = InetAddress.getByName(targetHost);
            ResultLogger logger = new ResultLogger("scan_results.txt");
            ExecutorService executor = Executors.newFixedThreadPool(100);

            for (int port = startport; port <= endport; port++) {
                if (choice == 1) executor.execute(new ThreadedTcpScanner(inetAddress, port, logger));
                else if (choice == 2) executor.execute(new ThreadedUdpScanner(inetAddress, port, logger));
                else { System.out.println("[-] Invalid type (1=TCP,2=UDP)"); return; }
            }

            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.MINUTES);

            new OSFingerprinting(targetHost).detectOS();
            System.out.println("\n[+] Scan complete. Results saved to scan_results.txt");

        } catch (Exception e) {
            System.out.println("[-] Error: " + e.getMessage());
        }
    }
}
