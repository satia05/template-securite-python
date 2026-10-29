import hashlib
import json
from unittest.mock import Mock

from tp2.main import main


def test_les_deux_formats_de_sortie(tmp_path, monkeypatch):
    dossier = tmp_path / "samples"
    dossier.mkdir()

    contenu = (
        b"c2.example.test\n"
        b"FLAG=ESGI{test_cli}\n"
    )

    fichier = dossier / "exemple.bin"
    fichier.write_bytes(contenu)

    regles = tmp_path / "test.txt"
    regles.write_text(
        'rule Test_Domaine { '
        'strings: $a = "c2.example.test" '
        'condition: $a }'
    )

    post = Mock(
        side_effect=AssertionError("Aucun réseau attendu")
    )
    monkeypatch.setattr("tp2.utils.llm.requests.post", post)

    # Contrat du template : rapport à côté de l'échantillon.
    assert main([
        "--file", str(fichier),
        "--rules", str(regles),
    ]) == 0

    rapport = dossier / "exemple.bin.triage.json"
    assert rapport.is_file()

    resultat = json.loads(
        rapport.read_text(encoding="utf-8")
    )

    sha256 = hashlib.sha256(contenu).hexdigest()

    assert resultat["sha256"] == sha256
    assert 0 <= resultat["entropy"] <= 8
    assert "c2.example.test" in resultat["iocs"]["domains"]
    assert resultat["yara_matches"] == ["Test_Domaine"]
    assert resultat["flag"] == "ESGI{test_cli}"

    # Contrat du sujet initial : rapport nommé avec le SHA-256.
    sortie = tmp_path / "rapports"

    assert main([
        "--samples", str(dossier),
        "--rules", str(regles),
        "--out", str(sortie),
    ]) == 0

    rapports = list(sortie.glob("*.json"))

    # Les anciens rapports ne doivent pas devenir des échantillons.
    assert len(rapports) == 1
    assert rapports[0].name == "exemple.bin.triage.json"

    resultat_dossier = json.loads(
        rapports[0].read_text(encoding="utf-8")
    )
    assert resultat_dossier == resultat

    post.assert_not_called()