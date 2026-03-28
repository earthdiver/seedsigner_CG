from base import BaseTest, FlowStep, FlowTest

from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.decode_qr import DecodeQR, SeedPayloadAnalysis
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import scan_views
from seedsigner.views.view import Destination, MainMenuView


AMBIGUOUS_SEGMENT = bytes([0] * 32)
ENCRYPTED_PUBLIC_DATA = "Encrypted QR Code:\nID: test"


class FakeEncryptedQR:
    def decrypt(self, _encryption_key: str):
        return AMBIGUOUS_SEGMENT


def make_ambiguous_analysis(segment: bytes) -> SeedPayloadAnalysis:
    return SeedPayloadAnalysis(
        segment=segment,
        candidate_types=[QRType.SEED__COMPACTSEEDQR, QRType.SEED__ENCRYPTEDQR],
        public_data=ENCRYPTED_PUBLIC_DATA,
        encrypted_qr=FakeEncryptedQR(),
    )


class TestSeedQRAmbiguityDetection(BaseTest):
    def test_detect_segment_type_prefers_compact_when_setting_is_compact(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__COMPACT,
            save=False,
        )
        monkeypatch.setattr(
            DecodeQR,
            "_parse_encrypted_qr",
            staticmethod(lambda _segment: (FakeEncryptedQR(), ENCRYPTED_PUBLIC_DATA)),
        )

        decoder = DecodeQR()

        assert (
            decoder.detect_segment_type(
                AMBIGUOUS_SEGMENT,
                wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
            )
            == QRType.SEED__COMPACTSEEDQR
        )

    def test_detect_segment_type_returns_ambiguous_when_setting_is_prompt(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        monkeypatch.setattr(
            DecodeQR,
            "_parse_encrypted_qr",
            staticmethod(lambda _segment: (FakeEncryptedQR(), ENCRYPTED_PUBLIC_DATA)),
        )

        decoder = DecodeQR()

        assert (
            decoder.detect_segment_type(
                AMBIGUOUS_SEGMENT,
                wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
            )
            == QRType.SEED__AMBIGUOUS
        )

    def test_detect_segment_type_prefers_encrypted_and_stores_candidate(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__ENCRYPTED,
            save=False,
        )
        fake_encrypted_qr = FakeEncryptedQR()
        monkeypatch.setattr(
            DecodeQR,
            "_parse_encrypted_qr",
            staticmethod(lambda _segment: (fake_encrypted_qr, ENCRYPTED_PUBLIC_DATA)),
        )

        decoder = DecodeQR()
        qr_type = decoder.detect_segment_type(
            AMBIGUOUS_SEGMENT,
            wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
        )

        assert qr_type == QRType.SEED__ENCRYPTEDQR
        stored = self.controller.storage2.encryptedqr
        assert stored is not None
        assert stored.encrypted_qr is fake_encrypted_qr
        assert stored.public_data == ENCRYPTED_PUBLIC_DATA


class TestSeedQRAmbiguityFlows(FlowTest):
    def test_scan_ambiguous_seed_qr_can_route_to_encrypted_key_view(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        monkeypatch.setattr(
            DecodeQR,
            "analyze_seed_payload",
            staticmethod(make_ambiguous_analysis),
        )

        def load_ambiguous_segment(view: scan_views.ScanView):
            view.decoder.add_data(AMBIGUOUS_SEGMENT)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_ambiguous_segment),
            FlowStep(
                scan_views.ScanAmbiguousSeedQRPromptView,
                button_data_selection=scan_views.ScanAmbiguousSeedQRPromptView.ENCRYPTED,
            ),
            FlowStep(
                scan_views.ScanEncryptedQREncryptionKeyView,
                button_data_selection=ButtonOption("Cancel"),
            ),
            FlowStep(MainMenuView),
        ])

    def test_decrypt_route_returns_prompt_for_nested_ambiguous_payload(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        monkeypatch.setattr(
            DecodeQR,
            "analyze_seed_payload",
            staticmethod(make_ambiguous_analysis),
        )

        view = scan_views.ScanDecryptEncryptedQRView(encryption_key="outer key", encrypted_data=b"unused")
        destination = view._route_decrypted_payload(AMBIGUOUS_SEGMENT)

        assert isinstance(destination, Destination)
        assert destination.View_cls == scan_views.ScanAmbiguousSeedQRPromptView
        assert destination.view_args["segment"] == AMBIGUOUS_SEGMENT
        assert destination.view_args["candidate_types"] == [
            QRType.SEED__COMPACTSEEDQR,
            QRType.SEED__ENCRYPTEDQR,
        ]
        assert destination.view_args["public_data"] == ENCRYPTED_PUBLIC_DATA
