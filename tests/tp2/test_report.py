import json
import re
from unittest.mock import Mock

import pytest
from fpdf.errors import FPDFException

from tp2.main import main
from tp2.utils.report import Report, pdf_text


def test_pdf_text():
    assert pdf_text("Analyse à vérifier") == "Analyse à vérifier"
    assert pdf_text("x\x00y") == "xy"
    assert pdf_text("测试") == r"\u6d4b\u8bd5"


def test_generate_pdf(tmp_path, caplog):
    caplog.set_level("INFO", logger="TP2")

    destination = tmp_path / "rapport.pdf"

    Report({
        "score": 6,
        "flag": "ESGI{test}",
    }).generate_pdf(str(destination))

    data = destination.read_bytes()

    assert data.startswith(b"%PDF-")
    assert data.rstrip().endswith(b"%%EOF")
    assert len(data) > 1000
    assert "PDF écrit" in caplog.text


def test_pdf_long_et_unicode(tmp_path):
    resultat = {
        "llm_summary": "Analyse 🔒 à vérifier. " * 200,
        "iocs": {
            "domains": [
                f"domaine-{i}.example.test"
                for i in range(80)
            ],
        },
        "imports": ["fonction_" + "x" * 250],
    }

    report = Report(resultat)

    destination_pdf = tmp_path / "rapport.pdf"
    report.generate_pdf(str(destination_pdf))

    pages = re.findall(
        rb"/Type\s*/Page\b",
        destination_pdf.read_bytes(),
    )
    assert len(pages) >= 2

    # La préparation du PDF ne doit pas modifier les données.
    destination_json = tmp_path / "rapport.json"
    report.generate_json(str(destination_json))

    assert json.loads(
        destination_json.read_text(encoding="utf-8")
    ) == resultat


def test_pdf_dossier_absent(tmp_path):
    with pytest.raises(OSError):
        Report({}).generate_pdf(
            str(tmp_path / "absent" / "rapport.pdf")
        )


@pytest.mark.parametrize("erreur_pdf", [False, True])
def test_main_pdf(tmp_path, monkeypatch, erreur_pdf):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(b"FLAG=ESGI{test_pdf}\n")

    regles = tmp_path / "test.txt"
    regles.write_text(
        "rule Test { condition: filesize > 0 }"
    )

    sortie = tmp_path / "out"

    post = Mock(
        side_effect=AssertionError("Aucun réseau attendu")
    )
    monkeypatch.setattr("tp2.utils.llm.requests.post", post)

    if erreur_pdf:
        monkeypatch.setattr(
            Report,
            "generate_pdf",
            Mock(
                side_effect=FPDFException("Erreur simulée")
            ),
        )

    retour = main([
        "--file", str(fichier),
        "--rules", str(regles),
        "--out", str(sortie),
    ])

    assert retour == (1 if erreur_pdf else 0)
    assert len(list(sortie.glob("*.json"))) == 1

    if not erreur_pdf:
        rapports = list(sortie.glob("*.pdf"))

        assert len(rapports) == 1
        assert rapports[0].read_bytes().startswith(b"%PDF-")

    post.assert_not_called()