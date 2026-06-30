import json
import base64
import io
import os
import traceback
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

try:
    import warnings
    warnings.filterwarnings("ignore")
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw, Ether
    from scapy.layers.dns import DNS
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def parse_pcap_bytes(pcap_bytes):
    packets = []
    try:
        f = io.BytesIO(pcap_bytes)
        # Try pcapng first, fall back to pcap
        try:
            from scapy.utils import PcapNgReader
            capture = PcapNgReader(f)
            pkts = list(capture)
        except Exception:
            f.seek(0)
            capture = rdpcap(f)
            pkts = list(capture)

        for i, pkt in enumerate(pkts[:500]):
            info = parse_packet(i + 1, pkt)
            packets.append(info)
    except Exception as e:
        raise ValueError(f'Failed to parse PCAP: {str(e)}')
    return packets


def parse_packet(num, pkt):
    """Extract key fields from a scapy packet."""
    info = {
        'no': num,
        'time': f'{float(pkt.time):.6f}',
        'src': '',
        'dst': '',
        'protocol': 'Unknown',
        'length': len(pkt),
        'info': '',
        'layers': [],
        'raw_hex': bytes(pkt).hex(),
    }

    # Layer detection
    if pkt.haslayer('IP'):
        ip = pkt['IP']
        info['src'] = ip.src
        info['dst'] = ip.dst
        info['layers'].append('IP')

        if pkt.haslayer('TCP'):
            tcp = pkt['TCP']
            info['protocol'] = 'TCP'
            info['layers'].append('TCP')
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            flag_str = []
            if flags & 0x02: flag_str.append('SYN')
            if flags & 0x10: flag_str.append('ACK')
            if flags & 0x01: flag_str.append('FIN')
            if flags & 0x04: flag_str.append('RST')
            if flags & 0x08: flag_str.append('PSH')
            info['info'] = f'{sport} → {dport} [{", ".join(flag_str) or ""}]'

            # Detect HTTP
            if sport == 80 or dport == 80:
                info['protocol'] = 'HTTP'
                if pkt.haslayer(Raw):
                    raw = pkt[Raw].load
                    try:
                        decoded = raw.decode('utf-8', errors='replace')
                        first_line = decoded.split('\r\n')[0]
                        info['info'] = first_line[:80]
                    except Exception:
                        pass
            elif sport == 443 or dport == 443:
                info['protocol'] = 'TLS'
                info['info'] = f'TLS {sport} → {dport}'

            elif sport == 22 or dport == 22:
                info['protocol'] = 'SSH'

            elif sport == 21 or dport == 21:
                info['protocol'] = 'FTP'
                if pkt.haslayer(Raw):
                    try:
                        info['info'] = pkt[Raw].load.decode('utf-8', errors='replace').strip()[:80]
                    except Exception:
                        pass

            elif sport == 25 or dport == 25:
                info['protocol'] = 'SMTP'

        elif pkt.haslayer('UDP'):
            udp = pkt['UDP']
            info['protocol'] = 'UDP'
            info['layers'].append('UDP')
            sport, dport = udp.sport, udp.dport
            info['info'] = f'{sport} → {dport}'

            if pkt.haslayer('DNS'):
                dns = pkt['DNS']
                info['protocol'] = 'DNS'
                info['layers'].append('DNS')
                try:
                    if dns.qr == 0 and dns.qdcount > 0:
                        qname = dns.qd.qname.decode('utf-8', errors='replace').rstrip('.')
                        info['info'] = f'Query: {qname}'
                    else:
                        info['info'] = f'Response ({dns.ancount} answers)'
                except Exception:
                    info['info'] = 'DNS'

        elif pkt.haslayer('ICMP'):
            icmp = pkt['ICMP']
            info['protocol'] = 'ICMP'
            info['layers'].append('ICMP')
            types = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'Time Exceeded'}
            info['info'] = types.get(icmp.type, f'Type {icmp.type}')

    elif pkt.haslayer('Ether'):
        eth = pkt['Ether']
        info['src'] = eth.src
        info['dst'] = eth.dst
        info['protocol'] = 'Ethernet'
        info['layers'].append('Ether')
        info['info'] = f'Type: {hex(eth.type)}'

    return info


def parse_raw_text(text):
    """Parse tcpdump-style text output into packet rows."""
    packets = []
    lines = [l.strip() for l in text.strip().split('\n') if l.strip()]
    for i, line in enumerate(lines[:200]):
        pkt = {
            'no': i + 1,
            'time': '',
            'src': '',
            'dst': '',
            'protocol': 'Unknown',
            'length': 0,
            'info': line,
            'layers': [],
            'raw_hex': '',
        }

        # Try to parse tcpdump format: "HH:MM:SS.us IP src > dst: ..."
        import re
        time_match = re.match(r'^(\d+:\d+:\d+\.\d+)\s+', line)
        if time_match:
            pkt['time'] = time_match.group(1)
            rest = line[time_match.end():]
        else:
            rest = line

        # IP packets
        ip_match = re.match(r'IP\s+([\d\.]+)\.?(\d+)?\s*>\s*([\d\.]+)\.?(\d+)?:\s*(.*)', rest)
        if ip_match:
            pkt['src'] = ip_match.group(1)
            pkt['dst'] = ip_match.group(3)
            pkt['info'] = ip_match.group(5)[:100]
            pkt['protocol'] = 'IP'

            sport = ip_match.group(2) or ''
            dport = ip_match.group(4) or ''

            detail = ip_match.group(5).lower()
            if 'flags' in detail or 'seq' in detail or 'ack' in detail:
                pkt['protocol'] = 'TCP'
            if 'udp' in detail:
                pkt['protocol'] = 'UDP'
            if sport in ('53', '') and 'a?' in detail.lower():
                pkt['protocol'] = 'DNS'
            if sport == '80' or dport == '80':
                pkt['protocol'] = 'HTTP'
            if sport == '443' or dport == '443':
                pkt['protocol'] = 'TLS'

        packets.append(pkt)
    return packets


@login_required
def packet_tracer(request):
    return render(request, 'packet_tracer.html')


@login_required
def analyze_packets(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    import traceback
    data = json.loads(request.body)
    mode = data.get('mode', 'text')

    try:
        if mode == 'pcap':
            if not SCAPY_AVAILABLE:
                return JsonResponse({'error': 'scapy is not installed. Run: pip install scapy'}, status=500)
            b64 = data.get('pcap_b64', '')
            pcap_bytes = base64.b64decode(b64)
            packets = parse_pcap_bytes(pcap_bytes)
        else:
            raw_text = data.get('text', '')
            packets = parse_raw_text(raw_text)

        proto_counts = {}
        for p in packets:
            proto = p['protocol']
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

        return JsonResponse({'packets': packets, 'total': len(packets), 'proto_counts': proto_counts})

    except Exception as e:
        traceback.print_exc()  # ← this prints full error to terminal
        return JsonResponse({'error': str(e)}, status=500)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)