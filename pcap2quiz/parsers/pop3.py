from collections import Counter
from pcap2quiz.parsers.base import BaseExtractor


class POP3Extractor(BaseExtractor):
    """
    POP3 コマンド、レスポンス、ユーザーログイン試行等の情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.pop3_commands = Counter()
        self.pop3_responses = Counter()
        self.user_logins = set()
        self.samples = []

    @property
    def name(self) -> str:
        return "POP3 Sessions & Commands"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'pop') or hasattr(packet, 'pop3')

    def process_packet(self, packet):
        pop = getattr(packet, 'pop', getattr(packet, 'pop3', None))
        if not pop:
            return

        req_cmd = getattr(pop, 'request_command', getattr(pop, 'command', '')).strip()
        req_arg = getattr(pop, 'request_parameter', getattr(pop, 'request_arg', '')).strip()
        resp_indicator = getattr(pop, 'response_indicator', getattr(pop, 'response', '')).strip()
        resp_desc = getattr(pop, 'response_description', '').strip()

        if req_cmd:
            self.pop3_commands[req_cmd.upper()] += 1
            if req_cmd.upper() == 'USER' and req_arg:
                self.user_logins.add(req_arg)
            sample = f"Request: {req_cmd} {req_arg}".strip()
            if sample not in self.samples and len(self.samples) < 10:
                self.samples.append(sample)

        if resp_indicator:
            resp_str = f"{resp_indicator} {resp_desc}".strip()
            self.pop3_responses[resp_str] += 1

    def format_summary(self) -> str:
        if not self.pop3_commands and not self.pop3_responses and not self.samples and not self.user_logins:
            return ""

        summary_text = f"[{self.name}]\n"

        if self.user_logins:
            summary_text += f"- Attempted User Logins: {', '.join(sorted(self.user_logins))}\n"

        if self.pop3_commands:
            summary_text += "- Top POP3 Commands:\n"
            for cmd, count in self.pop3_commands.most_common(5):
                summary_text += f"  - {cmd}: {count} times\n"

        if self.samples:
            summary_text += "- Sample POP3 Requests:\n"
            for sample in self.samples[:10]:
                summary_text += f"  - {sample}\n"

        if self.pop3_responses:
            summary_text += "- Top POP3 Responses:\n"
            for resp, count in self.pop3_responses.most_common(5):
                summary_text += f"  - {resp}: {count} times\n"

        return summary_text + "\n"
