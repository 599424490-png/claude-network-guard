using System;
using System.Net;
using System.Net.Sockets;

class NetworkRuleProbe {
    static string Probe(string address, int port) {
        using (var socket = new Socket(IPAddress.Parse(address).AddressFamily, SocketType.Stream, ProtocolType.Tcp)) {
            try {
                var pending = socket.BeginConnect(IPAddress.Parse(address), port, null, null);
                if (!pending.AsyncWaitHandle.WaitOne(2000)) return "timeout";
                socket.EndConnect(pending);
                return "connected";
            } catch (SocketException exception) {
                return exception.NativeErrorCode == 10013 ? "blocked-by-firewall" : "socket-error-" + exception.NativeErrorCode;
            }
        }
    }
    static int Main() {
        string loopback = Probe("127.0.0.1", 7897);
        string ipv4 = Probe("1.1.1.1", 443);
        string ipv6 = Probe("2606:4700:4700::1111", 443);
        // Windows can reject an IPv6 destination before WFP classification
        // when the host has no IPv6 route. Keep this distinct from a proven
        // firewall denial; the installer also verifies the IPv6 rule itself.
        bool ok = loopback == "connected" && ipv4 == "blocked-by-firewall" &&
            (ipv6 == "blocked-by-firewall" || ipv6 == "socket-error-10051");
        Console.WriteLine("{\"ok\":" + (ok ? "true" : "false") + ",\"loopback\":\"" + loopback + "\",\"ipv4\":\"" + ipv4 + "\",\"ipv6\":\"" + ipv6 + "\"}");
        return ok ? 0 : 1;
    }
}
