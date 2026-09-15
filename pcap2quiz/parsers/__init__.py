from pcap2quiz.parsers.base import BaseExtractor, ProtocolManager
from pcap2quiz.parsers.flow import FlowExtractor
from pcap2quiz.parsers.dns import DNSExtractor
from pcap2quiz.parsers.http import HTTPExtractor
from pcap2quiz.parsers.tls import TLSExtractor
from pcap2quiz.parsers.smb import SMBExtractor
from pcap2quiz.parsers.ftp import FTPExtractor
from pcap2quiz.parsers.smtp import SMTPExtractor
from pcap2quiz.parsers.pop3 import POP3Extractor
from pcap2quiz.parsers.imap import IMAPExtractor


def get_default_manager() -> ProtocolManager:
    """
    デフォルトの各プロトコル抽出器が登録された ProtocolManager を生成して返す
    新しいプロトコル抽出器を追加した場合は、ここに登録を追加する
    """
    manager = ProtocolManager()
    manager.register(FlowExtractor())
    manager.register(DNSExtractor())
    manager.register(HTTPExtractor())
    manager.register(TLSExtractor())
    manager.register(SMBExtractor())
    manager.register(FTPExtractor())
    manager.register(SMTPExtractor())
    manager.register(POP3Extractor())
    manager.register(IMAPExtractor())
    return manager


__all__ = [
    "BaseExtractor",
    "ProtocolManager",
    "FlowExtractor",
    "DNSExtractor",
    "HTTPExtractor",
    "TLSExtractor",
    "SMBExtractor",
    "FTPExtractor",
    "SMTPExtractor",
    "POP3Extractor",
    "IMAPExtractor",
    "get_default_manager",
]
