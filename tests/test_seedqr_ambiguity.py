from base import BaseTest, FlowStep, FlowTest

from seedsigner.helpers import kef
from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import scan_views
from seedsigner.views.view import MainMenuView

from test_encryption_vectors import ECB_ENCRYPTED_QR


OUTER_KEY = "outer key"
OUTER_ID = b"outer id"
OUTER_VERSION = 5
OUTER_ITERATIONS = 100000


def build_nested_encrypted_qr(inner_payload: bytes) -> bytes:
    cipher = kef.Cipher(OUTER_KEY, OUTER_ID, OUTER_ITERATIONS)
    encrypted_payload = cipher.encrypt(inner_payload, OUTER_VERSION)
    return kef.wrap(OUTER_ID, OUTER_VERSION, OUTER_ITERATIONS, encrypted_payload)


class TestSeedQRAmbiguity(BaseTest):
    def test_detect_segment_type_prefers_compactseedqr_by_default(self):
        decoder = DecodeQR()

        assert decoder.detect_segment_type(ECB_ENCRYPTED_QR) == QRType.SEED__COMPACTSEEDQR

    def test_detect_segment_type_prompts_for_ambiguous_seed_qr(self):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        decoder = DecodeQR()

        assert decoder.detect_segment_type(ECB_ENCRYPTED_QR) == QRType.SEED__AMBIGUOUS


class TestSeedQRAmbiguityFlows(FlowTest):
    def test_scan_ambiguous_seed_qr_can_be_routed_to_encrypted_flow(self):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )

        def load_ambiguous_encrypted_qr(view: scan_views.ScanView):
            view.decoder.add_data(ECB_ENCRYPTED_QR)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_ambiguous_encrypted_qr),
            FlowStep(
                scan_views.ScanAmbiguousSeedQRPromptView,
                button_data_selection=scan_views.ScanAmbiguousSeedQRPromptView.ENCRYPTED,
            ),
            FlowStep(scan_views.ScanEncryptedQREncryptionKeyView),
        ])

    def test_nested_encrypted_qr_prompts_before_redecrypting(self):
        self.settings.set_value(
            SettingsConstants.SETTING__AMBIGUOUS_SEED_QR,
            SettingsConstants.AMBIGUOUS_SEED_QR__PROMPT,
            save=False,
        )
        nested_payload = build_nested_encrypted_qr(ECB_ENCRYPTED_QR)

        self.run_sequence(
            [
                FlowStep(scan_views.ScanDecryptEncryptedQRView, is_redirect=True),
                FlowStep(
                    scan_views.ScanAmbiguousSeedQRPromptView,
                    button_data_selection=scan_views.ScanAmbiguousSeedQRPromptView.ENCRYPTED,
                ),
                FlowStep(scan_views.ScanEncryptedQREncryptionKeyView),
            ],
            initial_destination_view_args={
                "encryption_key": OUTER_KEY,
                "encrypted_data": nested_payload,
            },
        )
