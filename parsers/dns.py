from collections import Counter
from parsers.base import BaseExtractor


class DNSExtractor(BaseExtractor):
    """
    DNS クエリ情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.dns_queries = Counter()

    @property
    def name(self) -> str:
        return "DNS Queries"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'dns')

    def process_packet(self, packet):
        if hasattr(packet.dns, 'qry_name'):
            self.dns_queries[packet.dns.qry_name] += 1

    def format_summary(self) -> str:
        if not self.dns_queries:
            return ""

        summary_text = f"[{self.name}]\n"
        for qname, count in self.dns_queries.most_common(15):
            summary_text += f"- {qname}: {count} times\n"
        return summary_text + "\n"
