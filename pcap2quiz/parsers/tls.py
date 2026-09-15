from collections import Counter
from pcap2quiz.parsers.base import BaseExtractor


class TLSExtractor(BaseExtractor):
    """
    TLS / SSL SNI (Server Name Indication) 情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.tls_snis = Counter()

    @property
    def name(self) -> str:
        return "TLS Server Name Indication (SNI)"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'tls') or hasattr(packet, 'ssl')

    def process_packet(self, packet):
        tls_layer = packet.tls if hasattr(packet, 'tls') else packet.ssl
        sni = getattr(tls_layer, 'handshake_extensions_server_name', '')
        if sni:
            self.tls_snis[sni] += 1

    def format_summary(self) -> str:
        if not self.tls_snis:
            return ""

        summary_text = f"[{self.name}]\n"
        for sni, count in self.tls_snis.most_common(10):
            summary_text += f"- {sni}: {count} times\n"
        return summary_text + "\n"
