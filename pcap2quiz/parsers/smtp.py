from collections import Counter
from pcap2quiz.parsers.base import BaseExtractor


class SMTPExtractor(BaseExtractor):
    """
    SMTP コマンド、レスポンス、送信元/送信先メールアドレス等の情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.smtp_commands = Counter()
        self.smtp_responses = Counter()
        self.mail_from_set = set()
        self.rcpt_to_set = set()
        self.samples = []

    @property
    def name(self) -> str:
        return "SMTP Sessions & Commands"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'smtp')

    def process_packet(self, packet):
        smtp = packet.smtp

        req_cmd = getattr(smtp, 'req_command', getattr(smtp, 'command_line', '')).strip()
        req_param = getattr(smtp, 'req_parameter', '').strip()
        resp_code = getattr(smtp, 'response_code', '').strip()
        resp_para = getattr(smtp, 'response_para', '').strip()

        mail_from = getattr(smtp, 'mail_from', '').strip()
        rcpt_to = getattr(smtp, 'rcpt_to', '').strip()

        if mail_from:
            self.mail_from_set.add(mail_from)
        if rcpt_to:
            self.rcpt_to_set.add(rcpt_to)

        if req_cmd:
            self.smtp_commands[req_cmd.upper()] += 1
            sample = f"Command: {req_cmd} {req_param}".strip()
            if sample not in self.samples and len(self.samples) < 10:
                self.samples.append(sample)

        if resp_code:
            resp_str = f"{resp_code} {resp_para}".strip()
            self.smtp_responses[resp_str] += 1

    def format_summary(self) -> str:
        if not self.smtp_commands and not self.smtp_responses and not self.samples and not self.mail_from_set and not self.rcpt_to_set:
            return ""

        summary_text = f"[{self.name}]\n"

        if self.mail_from_set:
            summary_text += f"- Mail From: {', '.join(sorted(self.mail_from_set))}\n"
        if self.rcpt_to_set:
            summary_text += f"- Rcpt To: {', '.join(sorted(self.rcpt_to_set))}\n"

        if self.smtp_commands:
            summary_text += "- Top SMTP Commands:\n"
            for cmd, count in self.smtp_commands.most_common(5):
                summary_text += f"  - {cmd}: {count} times\n"

        if self.samples:
            summary_text += "- Sample SMTP Requests:\n"
            for sample in self.samples[:10]:
                summary_text += f"  - {sample}\n"

        if self.smtp_responses:
            summary_text += "- Top SMTP Responses:\n"
            for resp, count in self.smtp_responses.most_common(5):
                summary_text += f"  - {resp}: {count} times\n"

        return summary_text + "\n"
