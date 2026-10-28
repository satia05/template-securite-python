import pytest

from tp2.utils.sample import Sample


def test_sample_init(tmp_path):
    fichier = tmp_path / "exemple.txt"
    fichier.write_bytes(b"abc")

    sample = Sample(str(fichier))

    assert sample.data == b"abc"
    assert sample.path == str(fichier)


def test_get_file_metadata(tmp_path):
    fichier = tmp_path / "exemple.txt"
    fichier.write_bytes(b"abc")

    sample = Sample(str(fichier))
    resultat = sample.get_file_metadata()

    assert resultat["size"] == 3
    assert resultat["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert resultat["sha256"] == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert isinstance(resultat["file_type"], str)
    assert resultat["file_type"]
    assert resultat["entropy"] == pytest.approx(1.5849625)


@pytest.mark.parametrize(
    "contenu, entropie",
    [
        (b"", 0.0),
        (b"aaaa", 0.0),
        (bytes(range(256)), 8.0),
    ],
)
def test_shannon_entropy(tmp_path, contenu, entropie):
    fichier = tmp_path / "exemple.bin"
    fichier.write_bytes(contenu)

    sample = Sample(str(fichier))

    assert sample.shannon_entropy() == pytest.approx(entropie)