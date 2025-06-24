from flowcontainer.extractor import extract
import subprocess
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore")

MAX_PACKET_NUM = 5
MAX_PACKET_LENGTH = 1024
MAX_PAYLOAD_LENGTH = 128
HEX_PACKET_START_INDEX = 0  # 0 # 48 # 76

def build_flow_data(pcap_file, pnums, features):
    # fields selected by gemini 2.5 Pro
    fields = [
            # Frame-level information (useful for timing, length, and overall protocol stack)
            "frame.time", "frame.time_delta", "frame.time_relative", "frame.len", "frame.protocols",
            # Ethernet-level information (basic source/destination MAC and type)
            "eth.dst", "eth.src", "eth.type",
            # IP-level information (crucial for addressing, protocol, QoS, fragmentation flags, TTL)
            "ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len",
            "ip.flags", "ip.flags.df", "ip.flags.mf", "ip.ttl", "ip.proto", "ip.src", "ip.dst",
            # TCP-level information (ports, stream ID, segment length, header length, flags, window size, timing, analysis, payload)
            "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len", "tcp.hdr_len", "tcp.flags",
            "tcp.flags.cwr", "tcp.flags.urg", "tcp.flags.ack", "tcp.flags.push",
            "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str",
            "tcp.window_size", "tcp.time_relative", "tcp.time_delta",
            "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.reassembled.length",
            # TLS-level information (very useful for encrypted traffic identification)
            "tls.record.content_type", "tls.record.version", "tls.record.length",
            "tcp.payload",
            # UDP-level information (ports, length, stream ID)
            "udp.srcport", "udp.dstport", "udp.length", "udp.stream",
            # Data length (generic)
            "data.len"
        ]
        
        # tshark 3.6.16
    # ...existing code...
    # tshark 4
    # fields = ["frame.encap_type", "frame.time", "frame.offset_shift", "frame.time_epoch", "frame.time_delta",
    #             "frame.time_relative", "frame.number", "frame.len", "frame.marked", "frame.protocols", "eth.dst",
    #             "eth.dst_resolved", "eth.dst.oui", "eth.dst.oui_resolved", "eth.dst.lg", "eth.dst.ig", "eth.src",
    #             "eth.src_resolved", "eth.src.oui", "eth.src.oui_resolved", "eth.src.lg", "eth.src.ig", "eth.type",
    #             "ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
    #             "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto",
    #             "ip.checksum", "ip.checksum.status", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
    #             "tcp.completeness", "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
    #             "tcp.flags.res", "tcp.flags.cwr", "tcp.flags.urg", "tcp.flags.ack",
    #             "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str", "tcp.window_size",
    #             "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status", "tcp.urgent_pointer", "tcp.time_relative",
    #             "tcp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.segment", "tcp.segment.count",
    #             "tcp.reassembled.length", "tls.record.content_type", "tls.record.version", "tls.record.length", "tcp.payload", 
    #             "udp.srcport", "udp.dstport", "udp.length", "udp.checksum", "udp.checksum.status", "udp.stream", "data.len"]
    
    # tshark 3.6.16
    # fields = ["frame.encap_type", "frame.time", "frame.offset_shift", "frame.time_epoch", "frame.time_delta",
    #           "frame.time_relative", "frame.number", "frame.len", "frame.marked", "frame.protocols", "eth.dst",
    #           "eth.dst_resolved", "eth.dst.oui", "eth.dst.oui_resolved", "eth.dst.lg", "eth.dst.ig", "eth.src",
    #           "eth.src_resolved", "eth.src.oui", "eth.src.oui_resolved", "eth.src.lg", "eth.src.ig", "eth.type",
    #           "ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
    #           "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto",
    #           "ip.checksum", "ip.checksum.status", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
    #           "tcp.completeness", "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
    #           "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn", "tcp.flags.urg", "tcp.flags.ack",
    #           "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str", "tcp.window_size",
    #           "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status", "tcp.urgent_pointer", "tcp.time_relative",
    #           "tcp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.segment", "tcp.segment.count",
    #           "tcp.reassembled.length", "tls.record.content_type", "tls.record.version", "tls.record.length", "tcp.payload"]

    # tshark 2.6.10
    # fields = ["frame.encap_type", "frame.time", "frame.offset_shift", "frame.time_epoch", "frame.time_delta",
    #           "frame.time_relative", "frame.number", "frame.len", "frame.marked", "frame.protocols", "eth.dst",
    #           "eth.dst_resolved", "eth.src", "eth.src_resolved", "eth.type",
    #           "ip.version", "ip.hdr_len", "ip.dsfield", "ip.dsfield.dscp", "ip.dsfield.ecn", "ip.len", "ip.id",
    #           "ip.flags", "ip.flags.rb", "ip.flags.df", "ip.flags.mf", "ip.frag_offset", "ip.ttl", "ip.proto",
    #           "ip.checksum", "ip.checksum.status", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
    #           "tcp.len", "tcp.seq", "tcp.nxtseq", "tcp.ack", "tcp.hdr_len", "tcp.flags",
    #           "tcp.flags.res", "tcp.flags.ns", "tcp.flags.cwr", "tcp.flags.ecn", "tcp.flags.urg", "tcp.flags.ack",
    #           "tcp.flags.push", "tcp.flags.reset", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.str",
    #           "tcp.window_size", "tcp.window_size_scalefactor", "tcp.checksum", "tcp.checksum.status", "tcp.urgent_pointer",
    #           "tcp.time_relative", "tcp.time_delta", "tcp.analysis.bytes_in_flight", "tcp.analysis.push_bytes_sent", "tcp.segment",
    #           "tcp.segment.count", "tcp.reassembled.length", "tcp.payload", "udp.srcport", "udp.dstport", "udp.length",
    #           "udp.checksum", "udp.checksum.status", "udp.stream", "data.len"]

    extract_str = "-e " + " -e ".join(fields)
    cmd = ['tshark', '-r', pcap_file, '-T', 'fields', extract_str]
    cmd = ' '.join(cmd)
    lines = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8').stdout.splitlines()

    build_data = []
    current_idx = 0
    
    for n, feature in tqdm(zip(pnums, features), total=len(pnums)):
        flow = lines[current_idx : current_idx + n]
        flow_data = ''
        for packet in flow:
            packet_data = ""
            values = packet.strip().split("\t")
            for field, value in zip(fields, values):
                if value == "":
                    continue
                # if field == "tcp.flags.str" and "\\\\" in value:
                #     value = value.encode("unicode_escape").decode("unicode_escape")
                if field == "tcp.payload" or field == "udp.payload":
                    value = value[:MAX_PAYLOAD_LENGTH] if len(value) > MAX_PAYLOAD_LENGTH else value
                packet_data += field + ": " + value +  ", "
            packet_data = packet_data[:-2]
            flow_data += '<pck>' + packet_data +  ' '
        flow_data += ' <feature>' + feature
        build_data.append(flow_data)
        current_idx += n

    return build_data