from collections import Counter
from pcap2quiz.parsers.base import BaseExtractor


class FTPExtractor(BaseExtractor):
    """
    FTP コマンドおよびレスポンス情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.ftp_requests = []
        self.ftp_commands = Counter()
        self.ftp_responses = Counter()
        self.user_logins = set()

    @property
    def name(self) -> str:
        return "FTP Sessions & Commands"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'ftp')

    def process_packet(self, packet):
        ftp = packet.ftp

        req_cmd = getattr(ftp, 'request_command', getattr(ftp, 'request_command_code', '')).strip()
        req_arg = getattr(ftp, 'request_arg', '').strip()
        resp_code = getattr(ftp, 'response_code', '').strip()
        resp_arg = getattr(ftp, 'response_arg', '').strip()

        if req_cmd:
            self.ftp_commands[req_cmd] += 1
            if req_cmd.upper() == 'USER' and req_arg:
                self.user_logins.add(req_arg)
            
            entry = f"Request: {req_cmd} {req_arg}".strip()
            if entry not in self.ftp_requests:
                self.ftp_requests.append(entry)

        if resp_code:
            resp_str = f"{resp_code} {resp_arg}".strip()
            self.ftp_responses[resp_str] += 1

    def format_summary(self) -> str:
        if not self.ftp_commands and not self.ftp_responses and not self.ftp_requests:
            return ""

        summary_text = f"[{self.name}]\n"

        if self.user_logins:
            summary_text += f"- Attempted User Logins: {', '.join(sorted(self.user_logins))}\n"

        if self.ftp_commands:
            summary_text += "- Top FTP Commands:\n"
            for cmd, count in self.ftp_commands.most_common(5):
                summary_text += f"  - {cmd}: {count} times\n"

        if self.ftp_requests:
            summary_text += "- Sample FTP Requests:\n"
            for req in self.ftp_requests[:10]:
                summary_text += f"  - {req}\n"

        if self.ftp_responses:
            summary_text += "- Top FTP Responses:\n"
            for resp, count in self.ftp_responses.most_common(5):
                summary_text += f"  - {resp}: {count} times\n"

        return summary_text + "\n"
