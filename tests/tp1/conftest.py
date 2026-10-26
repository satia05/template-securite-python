"""Tests TP1 hors ligne : aucun accès réseau ni fenêtre graphique."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

os.environ["MPLBACKEND"] = "Agg"
os.environ.setdefault("MPLCONFIGDIR", tempfile.mkdtemp(prefix="tp1-matplotlib-"))
os.environ.setdefault("XDG_CACHE_HOME", os.environ["MPLCONFIGDIR"])
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from tp1.utils.capture import Capture  # noqa: E402 — configurer Matplotlib avant l'import


@pytest.fixture(autouse=True)
def isolated_output(tmp_path, monkeypatch):
    """Tous les rapports et graphiques restent dans un dossier temporaire."""
    monkeypatch.chdir(tmp_path)
    yield
    import matplotlib.pyplot as plt

    plt.close("all")


@pytest.fixture
def capture():
    return Capture("test.pcap")


@pytest.fixture
def analyse_packets(capture, monkeypatch, capsys):
    """Observer la détection sans générer un PDF pour chaque scénario."""
    monkeypatch.setattr(capture, "_gen_summary", lambda: "rapport.pdf")

    def run(packets):
        capture.packet = packets
        capture.analyse()
        return capsys.readouterr().out

    return run
