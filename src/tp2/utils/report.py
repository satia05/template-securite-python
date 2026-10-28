import json
from fpdf import FPDF
from tp2.utils.config import logger


def pdf_text(value: object) -> str:
    """Adapter le texte à la police standard sans modifier le JSON."""
    texte = str(value).replace("\x00", "")

    return texte.encode(
        "latin-1",
        errors="backslashreplace",
    ).decode("latin-1")


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Créer un rapport lisible avec les résultats de l'analyse."""
        pdf = FPDF()
        pdf.set_margins(15, 15, 15)
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            0,
            12,
            "Rapport de triage statique",
            new_x="LMARGIN",
            new_y="NEXT",
        )

        resultat = self.result

        sections = [
            (
                "Informations du fichier",
                [
                    f"SHA-256 : {resultat.get('sha256', '')}",
                    f"MD5 : {resultat.get('md5', '')}",
                    f"Taille : {resultat.get('size', 0)} octets",
                    f"Type : {resultat.get('file_type', 'inconnu')}",
                    f"Entropie : {resultat.get('entropy', 0):.2f}",
                ],
            ),
            (
                "Verdict",
                [
                    "Famille supposée : "
                    + resultat.get("family_guess", "unknown"),
                    f"Score : {resultat.get('score', 0)}/10",
                    "Flag extrait : "
                    + (resultat.get("flag") or "Non trouvé"),
                    "Analyse statique : ces indices ne prouvent pas une infection.",
                ],
            ),
            (
                "Résumé",
                [resultat.get("llm_summary", "Aucun résumé")],
            ),
            (
                "Règles YARA",
                resultat.get("yara_matches", [])
                or ["Aucune correspondance"],
            ),
            (
                "MITRE ATT&CK - hypothèses",
                resultat.get("mitre_attack", [])
                or ["Aucune technique proposée"],
            ),
        ]

        for categorie, valeurs in resultat.get("iocs", {}).items():
            sections.append((
                f"IOC - {categorie}",
                valeurs or ["Aucun indicateur"],
            ))

        sections.append((
            "Imports",
            resultat.get("imports", [])
            or ["Aucun import identifié"],
        ))

        for titre, lignes in sections:
            # Éviter un titre tout en bas d'une page.
            if pdf.get_y() > pdf.h - 45:
                pdf.add_page()

            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(
                0,
                7,
                pdf_text(titre),
                new_x="LMARGIN",
                new_y="NEXT",
            )

            pdf.set_font("Helvetica", size=10)

            for ligne in lignes:
                pdf.multi_cell(
                    0,
                    6,
                    pdf_text(ligne),
                    new_x="LMARGIN",
                    new_y="NEXT",
                    wrapmode="CHAR",
                )

        pdf.output(out_pdf)
        logger.info("PDF écrit : %s", out_pdf)

    def generate_json(self, out_json: str) -> None:
        """Écrire le rapport machine-lisible."""
        with open(out_json, "w", encoding="utf-8") as fichier:
            json.dump(
                self.result,
                fichier,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )