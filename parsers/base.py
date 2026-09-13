from abc import ABC, abstractmethod


class BaseExtractor(ABC):
    """
    プロトコル抽出器の抽象基底クラス
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        抽出器の名称 / 表示タイトル
        """
        pass

    @abstractmethod
    def can_extract(self, packet) -> bool:
        """
        対象のパケットから情報抽出が可能か判定
        """
        pass

    @abstractmethod
    def process_packet(self, packet):
        """
        パケットから必要な情報を抽出・集計
        """
        pass

    @abstractmethod
    def format_summary(self) -> str:
        """
        集計結果をテキスト形式で出力
        """
        pass


class ProtocolManager:
    """
    登録された各プロトコル抽出器を一括管理・実行するマネージャー
    """

    def __init__(self):
        self.extractors: list[BaseExtractor] = []

    def register(self, extractor: BaseExtractor):
        """
        プロトコル抽出器を登録
        """
        self.extractors.append(extractor)
        return self

    def process_packet(self, packet):
        """
        登録されているすべての抽出器に対してパケット処理を実行
        """
        for extractor in self.extractors:
            if extractor.can_extract(packet):
                try:
                    extractor.process_packet(packet)
                except Exception:
                    # 個別プロトコル抽出のエラーで全停止しないようハンドリング
                    pass

    def generate_full_summary(self) -> str:
        """
        各抽出器のサマリを結合して最終テキストを生成
        """
        summary_sections = []
        for extractor in self.extractors:
            section = extractor.format_summary()
            if section:
                summary_sections.append(section)
        return "\n".join(summary_sections)
