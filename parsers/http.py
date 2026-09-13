from parsers.base import BaseExtractor


class HTTPExtractor(BaseExtractor):
    """
    HTTP リクエスト情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.http_requests = []

    @property
    def name(self) -> str:
        return "HTTP Requests (Sample)"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'http')

    def process_packet(self, packet):
        method = getattr(packet.http, 'request_method', '')
        uri = getattr(packet.http, 'request_full_uri', getattr(packet.http, 'request_uri', ''))
        host = getattr(packet.http, 'host', '')
        ua = getattr(packet.http, 'user_agent', '')
        if uri or host:
            self.http_requests.append(f"{method} {host}{uri} (UA: {ua})".strip())

    def format_summary(self) -> str:
        if not self.http_requests:
            return ""

        summary_text = f"[{self.name}]\n"
        for req in self.http_requests[:15]:
            summary_text += f"- {req}\n"
        return summary_text + "\n"
