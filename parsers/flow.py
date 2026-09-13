from collections import Counter
from parsers.base import BaseExtractor


class FlowExtractor(BaseExtractor):
    """
    IPペア通信量およびパケットフローサンプルを抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.ip_pairs = Counter()
        self.general_summary = []
        self.packet_count = 0

    @property
    def name(self) -> str:
        return "IP Traffic & Packet Flow"

    def can_extract(self, packet) -> bool:
        # すべてのパケットを対象とする
        return True

    def process_packet(self, packet):
        self.packet_count += 1

        src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
        dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'

        if src_ip != 'N/A' and dst_ip != 'N/A':
            self.ip_pairs[f"{src_ip} -> {dst_ip}"] += 1

        if len(self.general_summary) < 50:
            highest_layer = packet.highest_layer
            port_info = ""
            if hasattr(packet, 'transport_layer'):
                try:
                    layer = packet[packet.transport_layer]
                    src_port = getattr(layer, 'srcport', '')
                    dst_port = getattr(layer, 'dstport', '')
                    if src_port and dst_port:
                        port_info = f":{src_port} -> :{dst_port}"
                except Exception:
                    pass

            self.general_summary.append(
                f"#{self.packet_count} {highest_layer} | {src_ip}{port_info} -> {dst_ip}"
            )

    def format_summary(self) -> str:
        summary_text = ""
        if self.ip_pairs:
            summary_text += "[Top IP Traffic Pairs]\n"
            for pair, count in self.ip_pairs.most_common(10):
                summary_text += f"- {pair}: {count} packets\n"

        if self.general_summary:
            if summary_text:
                summary_text += "\n"
            summary_text += "[Packet Flow Sample]\n"
            summary_text += "\n".join(self.general_summary[:30]) + "\n"

        return summary_text
