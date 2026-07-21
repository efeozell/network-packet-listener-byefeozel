import scapy.all as scapy
from scapy.all import DNS, DNSQR, DNSRR, Raw
import optparse
from scapy.layers.http import HTTPRequest
from scapy.utils import PcapNgWriter
from datetime import datetime
from colorama import Fore, Style, init
init()
scapy.load_layer("tls")
from scapy.layers.tls.handshake import TLSClientHello

pcap_writer = None

def print_banner(options):
   print(Fore.GREEN + "╔══════════════════════════════════════╗")
   print(Fore.GREEN + "║    Network Sniffer by Efe Ozel v1.0  ║")
   print(Fore.GREEN + "╠══════════════════════════════════════╣")
   print(Fore.GREEN + f"║  Interface  : {options.iface:<23}║")
   print(Fore.GREEN + f"║  Output     : {options.output or 'None':<23}║")
   print(Fore.GREEN + f"║  Started    : {datetime.now().strftime('%H:%M:%S'):<23}║")
   print(Fore.GREEN + "║  Stop       : CTRL+C                 ║")
   print(Fore.GREEN + "╚══════════════════════════════════════╝" + Style.RESET_ALL)

def get_arguments():
   parse = optparse.OptionParser()
   parse.add_option("-i", "--iface", dest="iface", help="Select intenet interface")
   parse.add_option("-o", "--output", dest="output", help="If you want save network traffic to pcap file you can use.")

   options = parse.parse_args()[0]
   if not options.iface:
      options.iface = "eth0"
      print("It was set to eth0 because you didnt select")

   return options


def listen_packets(iface):
  scapy.sniff(iface=iface, store=False, prn=analyze_packets)


def analyze_packets(packet):

    timestamp = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(scapy.IP):
       src_ip = packet[scapy.IP].src
    else:
       src_ip = "unknown"

    if pcap_writer:
       pcap_writer.write(packet)


    if packet.haslayer(HTTPRequest):

      host = packet[HTTPRequest].Host.decode("utf-8")
      path = packet[HTTPRequest].Path.decode("utf-8")
      body = ""

      if packet.haslayer(Raw):
         body = packet[Raw].load.decode("utf-8", errors="ignore")
         print(Fore.RED + f"[{timestamp}] [{src_ip}] HTTP Request -> " + host + path + Style.RESET_ALL)
         print(Fore.YELLOW + f"[{timestamp}] [{src_ip}] Payload -> {body}" + Style.RESET_ALL)
      else:
        print(Fore.RED + f"[{timestamp}] [{src_ip}] HTTP Request -> " + host + path + Style.RESET_ALL)

    elif packet.haslayer(DNS):
       if packet.haslayer(DNSQR):
         qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
         print(Fore.BLUE + f"[{timestamp}] [{src_ip}] DNS Query -> {qname} " + Style.RESET_ALL)

       if packet.haslayer(DNSRR):
          rrname = packet[DNSRR].rrname.decode("utf-8", errors="ignore").rstrip(".")
          rdata = packet[DNSRR].rdata
          print(Fore.CYAN + f"[{timestamp}] [{src_ip}] DNS Response -> {rrname} : {rdata}" + Style.RESET_ALL)

    elif packet.haslayer(TLSClientHello):
       tls_hello = packet[TLSClientHello]
       if tls_hello.ext:
          for ext in tls_hello.ext:
             if hasattr(ext, "servernames"):
                for sn in ext.servernames:
                   sni = sn.servername.decode("utf-8", errors="ignore")
                   print(Fore.MAGENTA + f"[{timestamp}] [{src_ip}] TLS SNI -> {sni}" + Style.RESET_ALL)


if __name__ == "__main__":
   options = get_arguments()
   print_banner(options)

   if options.output:
      pcap_writer = PcapNgWriter(options.output)


   try:
      listen_packets(options.iface)
   except KeyboardInterrupt:
      print("\n [*] Stopped")
   except OSError as e:
      print(f"[-] Interface error: {e}")
   finally:
      if pcap_writer:
          pcap_writer.close()
          print(f"[+] PCAP Saved: {options.output}")





