from collections import Counter
from pcap2quiz.parsers.base import BaseExtractor


class IMAPExtractor(BaseExtractor):
    """
    IMAP コマンド、レスポンス、ユーザーログイン試行等の情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.imap_commands = Counter()
        self.imap_responses = Counter()
        self.user_logins = set()
        self.samples = []

    @property
    def name(self) -> str:
        return "IMAP Sessions & Commands"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'imap')

    def process_packet(self, packet):
        imap = packet.imap

        req_tag = getattr(imap, 'request_tag', '').strip()
        req_cmd = getattr(imap, 'request_command', getattr(imap, 'command', '')).strip()
        req_arg = getattr(imap, 'request_parameter', getattr(imap, 'request_arg', '')).strip()
        resp = getattr(imap, 'response', getattr(imap, 'response_status', '')).strip()

        if req_cmd:
            self.imap_commands[req_cmd.upper()] += 1
            if req_cmd.upper() == 'LOGIN' and req_arg:
                parts = req_arg.split()
                if parts:
                    self.user_logins.add(parts[0].strip('"\''))
            sample = f"Request: {req_tag} {req_cmd} {req_arg}".strip()
            if sample not in self.samples and len(self.samples) < 10:
                self.samples.append(sample)

        if resp:
            self.imap_responses[resp] += 1

    def format_summary(self) -> str:
        if not self.imap_commands and not self.imap_responses and not self.samples and not self.user_logins:
            return ""

        summary_text = f"[{self.name}]\n"

        if self.user_logins:
            summary_text += f"- Attempted User Logins: {', '.join(sorted(self.user_logins))}\n"

        if self.imap_commands:
            summary_text += "- Top IMAP Commands:\n"
            for cmd, count in self.imap_commands.most_common(5):
                summary_text += f"  - {cmd}: {count} times\n"

        if self.samples:
            summary_text += "- Sample IMAP Requests:\n"
            for sample in self.samples[:10]:
                summary_text += f"  - {sample}\n"

        if self.imap_responses:
            summary_text += "- Top IMAP Responses:\n"
            for resp, count in self.imap_responses.most_common(5):
                summary_text += f"  - {resp}: {count} times\n"

        return summary_text + "\n"
