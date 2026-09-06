"""
Utility to generate authentic libpcap files containing real email packet streams
for testing and verification purposes.
"""
from pathlib import Path
from scapy.utils import wrpcap
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

def create_sample_email_pcap(output_path: str):
    pkts = []
    
    # Stream 1: Plaintext SMTP with cleartext AUTH PLAIN (Port 25)
    # SYN, SYN-ACK, ACK
    pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.25")/TCP(sport=49152, dport=25, flags="S", seq=1000))
    pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.50")/TCP(sport=25, dport=49152, flags="SA", seq=2000, ack=1001))
    pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.25")/TCP(sport=49152, dport=25, flags="A", seq=1001, ack=2001))
    
    # Server Banner
    pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.50")/TCP(sport=25, dport=49152, flags="PA", seq=2001, ack=1001)/Raw(b"220 mail.enterprise.local ESMTP Postfix\r\n"))
    # Client EHLO
    pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.25")/TCP(sport=49152, dport=25, flags="PA", seq=1001, ack=2040)/Raw(b"EHLO workstation.local\r\n"))
    # Server EHLO Response
    pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.50")/TCP(sport=25, dport=49152, flags="PA", seq=2040, ack=1025)/Raw(b"250-mail.enterprise.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH PLAIN LOGIN\r\n"))
    # Client Cleartext AUTH PLAIN
    pkts.append(Ether()/IP(src="192.168.1.50", dst="10.0.0.25")/TCP(sport=49152, dport=25, flags="PA", seq=1025, ack=2110)/Raw(b"AUTH PLAIN AGVtcGxveWVlADEyMzQ1Ng==\r\n"))

    # Stream 2: SMTPS with TLS 1.0 (Port 465) - RFC 8996 Deprecated Version & 3DES
    pkts.append(Ether()/IP(src="192.168.1.51", dst="10.0.0.25")/TCP(sport=51234, dport=465, flags="S", seq=3000))
    pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.51")/TCP(sport=465, dport=51234, flags="SA", seq=4000, ack=3001))
    pkts.append(Ether()/IP(src="192.168.1.51", dst="10.0.0.25")/TCP(sport=51234, dport=465, flags="A", seq=3001, ack=4001))
    
    # Client Hello (TLS 1.0)
    client_hello = (
        b"\x16\x03\x01\x00\x30" +
        b"\x01\x00\x00\x2c" +
        b"\x03\x01" +
        (b"\x00" * 32) +
        b"\x00" +
        b"\x00\x04" +
        b"\x00\x0a\x00\x2f" +
        b"\x01\x00"
    )
    pkts.append(Ether()/IP(src="192.168.1.51", dst="10.0.0.25")/TCP(sport=51234, dport=465, flags="PA", seq=3001, ack=4001)/Raw(client_hello))

    # Server Hello (TLS 1.0, 3DES cipher chosen)
    server_hello = (
        b"\x16\x03\x01\x00\x2a" +
        b"\x02\x00\x00\x26" +
        b"\x03\x01" +
        (b"\x01" * 32) +
        b"\x00" +
        b"\x00\x0a" +
        b"\x00"
    )
    pkts.append(Ether()/IP(src="10.0.0.25", dst="192.168.1.51")/TCP(sport=465, dport=51234, flags="PA", seq=4001, ack=3054)/Raw(server_hello))

    # Stream 3: Secure IMAPS (Port 993) with TLS 1.3
    pkts.append(Ether()/IP(src="192.168.1.52", dst="10.0.0.99")/TCP(sport=55100, dport=993, flags="S", seq=5000))
    pkts.append(Ether()/IP(src="10.0.0.99", dst="192.168.1.52")/TCP(sport=993, dport=55100, flags="SA", seq=6000, ack=5001))
    pkts.append(Ether()/IP(src="192.168.1.52", dst="10.0.0.99")/TCP(sport=55100, dport=993, flags="A", seq=5001, ack=6001))

    # Server Hello with TLS 1.3 (0x1302: TLS_AES_256_GCM_SHA384) + supported_versions ext
    server_hello_tls13 = (
        b"\x16\x03\x03\x00\x32" +
        b"\x02\x00\x00\x2e" +
        b"\x03\x03" +
        (b"\x02" * 32) +
        b"\x00" +
        b"\x13\x02" +
        b"\x00" +
        b"\x00\x06" +
        b"\x00\x2b\x00\x02\x03\x04"
    )
    pkts.append(Ether()/IP(src="10.0.0.99", dst="192.168.1.52")/TCP(sport=993, dport=55100, flags="PA", seq=6001, ack=5001)/Raw(server_hello_tls13))

    wrpcap(output_path, pkts)
    return output_path

if __name__ == "__main__":
    sample_dir = Path(__file__).resolve().parent.parent / "data" / "samples"
    sample_dir.mkdir(parents=True, exist_ok=True)
    out = sample_dir / "sample_enterprise_email.pcap"
    create_sample_email_pcap(str(out))
    print(f"Generated authentic sample PCAP: {out}")
