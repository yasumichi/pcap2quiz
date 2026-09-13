from collections import Counter
from parsers.base import BaseExtractor


class SMBExtractor(BaseExtractor):
    """
    SMB / SMB2 コマンド情報を抽出するプロトコルアナライザー
    """

    def __init__(self):
        self.smb_commands = Counter()

    @property
    def name(self) -> str:
        return "SMB Commands"

    def can_extract(self, packet) -> bool:
        return hasattr(packet, 'smb') or hasattr(packet, 'smb2')

    def process_packet(self, packet):
        smb_cmd = getattr(packet.smb2, 'cmd', getattr(packet, 'smb', {}).get('cmd', 'Command'))
        self.smb_commands[smb_cmd] += 1

    def format_summary(self) -> str:
        if not self.smb_commands:
            return ""

        summary_text = f"[{self.name}]\n"
        for cmd, count in self.smb_commands.most_common(10):
            summary_text += f"- {cmd}: {count} times\n"
        return summary_text + "\n"
