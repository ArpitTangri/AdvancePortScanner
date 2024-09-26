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
            ProcessBuilder builder = new ProcessBuilder(List.of("ping", "-c", "1", host));
            Process process = builder.start();
            BufferedReader inputstream = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String s;
            while ((s = inputstream.readLine()) != null) {
                System.out.println(s);
            }

            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String OsVersion(String host) {
        try {
            ProcessBuilder builder = new ProcessBuilder("nmap", "-O", host);
            builder.redirectErrorStream(true);
            Process process = builder.start();

            BufferedReader inputstream = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String osinfo = null;
            String line;

            while ((line = inputstream.readLine()) != null) {
                if (line.contains("Running:")) {
                    osinfo = line;
                    break;
                }
            }

            process.waitFor();
            return osinfo;

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

            String osv = IcmpPinger.OsVersion(targetHost);
            System.out.println("(+)" + "Detected OS: " + (osv != null ? osv : "Unknown"));

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
