import pytest
from PIL import Image
from tp1.utils.report import Report


@pytest.fixture
def report(capture, tmp_path):
    return Report(capture, str(tmp_path / "report.txt"), "Résumé du trafic")


def test_report_init(report, capture):
    assert report.capture is capture
    assert report.title == "TITRE DU RAPPORT"
    assert report.summary == "Résumé du trafic"
    assert report.array == ""
    assert report.graph == ""


def test_concat_report(report):
    report.title = "Titre\n"
    report.array = "\nTableau"
    report.graph = "\nGraphique"
    assert report.concat_report() == "Titre\nRésumé du trafic\nTableau\nGraphique"


def test_save_writes_content(report, tmp_path):
    report.save(report.filename)
    assert (tmp_path / "report.txt").read_text() == report.concat_report()


def test_save_propagates_file_error(report, tmp_path):
    report.filename = str(tmp_path / "missing" / "report.txt")
    with pytest.raises(FileNotFoundError):
        report.save(report.filename)


def test_generate_graph_creates_png(report, tmp_path):
    report.capture.packet = []
    report.generate("graph")
    with Image.open(tmp_path / "graphique.png") as chart:
        assert chart.format == "PNG"
        chart.verify()


def test_unknown_generation_preserves_content(report):
    report.array = "tableau existant"
    report.graph = "graphique existant"
    report.generate("unknown")
    assert report.array == "tableau existant"
    assert report.graph == "graphique existant"


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Report.generate efface le chemin du graphique après création")
def test_generated_graph_path_is_retained(report):
    report.generate("graph")
    assert report.graph == "graphique.png"


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="La génération du tableau Report.array est encore vide")
def test_generated_array_contains_counts(report):
    report.generate("array")
    assert "Ethernet" in report.array
    assert "0" in report.array


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Report.save ignore son argument filename")
def test_save_uses_requested_filename(report, tmp_path):
    destination = tmp_path / "other.txt"
    report.save(str(destination))
    assert destination.exists()
    assert destination.read_text() == report.concat_report()
