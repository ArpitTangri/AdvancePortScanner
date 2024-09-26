import java.net.*;
import java.util.List;
import java.util.Scanner;
import java.io.*;
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
        System.out.println("(+)" + "scanner port on host " + inetaddress.getHostAddress());
    }
}
class TcpPortScanner extends PortScanner {
    public TcpPortScanner(String host, int startport, int endport) throws UnknownHostException {
        super(host, startport, endport);
    }
    public void scanPorts() {
        printScanDetails();
        for (int port = startport; port <= endport; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(inetaddress, port), 100);
                System.out.println("tcp port " + port + " is open");
            } catch (Exception ex) {
                // System.out.println("tcp port " + port + " is closed");
            }
        }
    }
    private void grabServiceBanner(Socket socket, int port) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String banner = in.readLine();
            if (banner != null) {
                System.out.println("banner for " + port + " :" + banner);
            }
        } catch (Exception e) {
            // System.out.println();
        }
    }
}
class UdpPortScanner extends PortScanner {
    public UdpPortScanner(String host, int startport, int endport) throws UnknownHostException {
        super(host, startport, endport);
    }
    public void scanPorts() {
        printScanDetails();
        for (int port = startport; port <= endport; port++) {
            try {
                DatagramSocket socket = new DatagramSocket();
                socket.setSoTimeout(200);
                byte[] buffer = new byte[1];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, inetaddress, port);
                socket.send(packet);
                socket.receive(packet);
                System.out.println("udp port " + port + " is open");
            } catch (Exception ex) {
                // System.out.println("udp port " + port + " is closed");
            }
        }
    }
}
class IcmpPinger {
    public static void pingHost(String host) {
        try {
            // Determine the correct ping command based on the OS
            String[] pingCommand;
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                pingCommand = new String[] { "ping", "-n", "1", host }; // Windows command
            } else {
                pingCommand = new String[] { "ping", "-c", "1", host }; // Linux/MacOS command
            }
            // Create a ProcessBuilder with the command
            ProcessBuilder builder = new ProcessBuilder(pingCommand);
            // Start the process
            Process p = builder.start();
            // Capture the standard output
            BufferedReader inputStream = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String s;
            System.out.println("Ping Output:");
            while ((s = inputStream.readLine()) != null) {
                System.out.println(s);
            }
            // Wait for the process to complete
            int exitCode = p.waitFor();
            if (exitCode == 0) {
                System.out.println("Ping successful!");
            } else {
                System.out.println("Ping failed with exit code: " + exitCode);
            }
        } catch (IOException | InterruptedException e) {
            System.out.println("Error executing ping command: " + e.getMessage());
        }
    }
    public static String OsVersion(String host) {
        try {
            // Create the process to run Nmap
            ProcessBuilder builder = new ProcessBuilder("nmap", "-O", host);
            builder.redirectErrorStream(true);  // Combine standard output and error stream
            // Start the process
            Process process = builder.start();
            // Use try-with-resources to automatically close the BufferedReader
            try (BufferedReader inputStream = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String osInfo = null;
                String line;
                // Read the output from Nmap
                while ((line = inputStream.readLine()) != null) {
                    if (line.contains("Running:")) {
                        osInfo = line;  // Capture the line containing OS information
                        break;
                    }
                }
                process.waitFor();  // Wait for the Nmap process to finish
                return osInfo;  // Return the detected OS information
            } catch (IOException e) {
                System.out.println("Error reading Nmap output: " + e.getMessage());
                return null;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return null;
        }
    }
}
public class AdvancePortScanner {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            System.out.print("(+)" + "Enter Target Host(IP or DOMAIN NAME): ");
            String targetHost = scanner.nextLine();
            System.out.print("(+)" + "Enter start port: ");
            int startport = scanner.nextInt();
            System.out.print("(+)" + "Enter end port: ");
            int endport = scanner.nextInt();
            System.out.println("(+)" + "pinging host...");
            IcmpPinger.pingHost(targetHost);
            System.out.println("(+)" + "Detecting OS using Nmap...");
            String osv = IcmpPinger.OsVersion(targetHost);
            // Print the detected OS, or "Unknown" if not detected
            if (osv != null) {
                System.out.println("(+)" + "Detected OS: " + osv);
            } else {
                System.out.println("(+)" + "OS detection failed or returned no result.");
            }
            System.out.print("(+)" + "Choose scan type (1 for TCP, 2 for UDP): ");
            int choice = scanner.nextInt();
            PortScanner ps;
            if (choice == 1) {
                ps = new TcpPortScanner(targetHost, startport, endport);
            } else if (choice == 2) {
                ps = new UdpPortScanner(targetHost, startport, endport);
            } else {
                System.out.println("Invalid choice");
                return;
            }
            ps.scanPorts();
        } catch (UnknownHostException ue) {
            System.out.println("Host could not be resolved: " + ue.getMessage());
        }
    }
}
