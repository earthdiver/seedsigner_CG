from base import BaseTest, FlowStep, FlowTest

from seedsigner.helpers import kef
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.decode_qr import DecodeQR, SeedPayloadAnalysis
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import scan_views
from seedsigner.views.view import MainMenuView

from test_encryption_vectors import ECB_ENCRYPTED_QR


OUTER_KEY = "outer key"
OUTER_ID = b"outer id"
OUTER_VERSION = 5
OUTER_ITERATIONS = 100000

AMBIGUOUS_SEGMENT = bytes([0] * 32)


class FakeEncryptedQR:
    def __init__(self, decrypted_payload: bytes = AMBIGUOUS_SEGMENT):
        self.decrypted_payload = decrypted_payload

    def decrypt(self, _encryption_key: str):
        return self.decrypted_payload


def ambiguous_analysis(segment: bytes) -> SeedPayloadAnalysis:
    return SeedPayloadAnalysis(
        segment=segment,
        candidate_types=[QRType.SEED__COMPACTSEEDQR, QRType.SEED__ENCRYPTEDQR],
        public_data="Encrypted QR Code:\nID: test",
        encrypted_qr=FakeEncryptedQR(),
    )


def build_nested_encrypted_qr(inner_payload: bytes) -> bytes:
    cipher = kef.Cipher(OUTER_KEY, OUTER_ID, OUTER_ITERATIONS)
    encrypted_payload = cipher.encrypt(inner_payload, OUTER_VERSION)
    return kef.wrap(OUTER_ID, OUTER_VERSION, OUTER_ITERATIONS, encrypted_payload)


class TestSeedQRAmbiguity(BaseTest):
    def test_detect_segment_type_prefers_compactseedqr_by_default(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__COMPACT,
            save=False,
        )
        monkeypatch.setattr(DecodeQR, "analyze_seed_payload", staticmethod(ambiguous_analysis))
        decoder = DecodeQR()

        assert (
            decoder.detect_segment_type(
                AMBIGUOUS_SEGMENT,
                wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
            )
            == QRType.SEED__COMPACTSEEDQR
        )

    def test_detect_segment_type_prompts_for_ambiguous_seed_qr(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        monkeypatch.setattr(DecodeQR, "analyze_seed_payload", staticmethod(ambiguous_analysis))
        decoder = DecodeQR()

        assert (
            decoder.detect_segment_type(
                AMBIGUOUS_SEGMENT,
                wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
            )
            == QRType.SEED__AMBIGUOUS
        )


class TestSeedQRAmbiguityFlows(FlowTest):
    def test_scan_ambiguous_seed_qr_can_be_routed_to_encrypted_flow(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        monkeypatch.setattr(DecodeQR, "analyze_seed_payload", staticmethod(ambiguous_analysis))

        def load_ambiguous_encrypted_qr(view: scan_views.ScanView):
            view.decoder.add_data(AMBIGUOUS_SEGMENT)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_ambiguous_encrypted_qr),
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

    def test_nested_encrypted_qr_prompts_before_redecrypting(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        nested_payload = build_nested_encrypted_qr(ECB_ENCRYPTED_QR)
        monkeypatch.setattr(DecodeQR, "analyze_seed_payload", staticmethod(ambiguous_analysis))
        monkeypatch.setattr(
            DecodeQR,
            "_parse_encrypted_qr",
            staticmethod(lambda _segment: (FakeEncryptedQR(AMBIGUOUS_SEGMENT), "Encrypted QR Code:\nID: test")),
        )

        self.run_sequence(
            [
                FlowStep(scan_views.ScanDecryptEncryptedQRView, is_redirect=True),
                FlowStep(
                    scan_views.ScanAmbiguousSeedQRPromptView,
                    button_data_selection=scan_views.ScanAmbiguousSeedQRPromptView.ENCRYPTED,
                ),
                FlowStep(
                    scan_views.ScanEncryptedQREncryptionKeyView,
                    button_data_selection=ButtonOption("Cancel"),
                ),
                FlowStep(MainMenuView),
            ],
            initial_destination_view_args={
                "encryption_key": OUTER_KEY,
                "encrypted_data": nested_payload,
            },
        )
