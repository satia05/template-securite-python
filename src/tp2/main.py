import argparse
from pathlib import Path

import yara

from tp2.utils.triage import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage

from fpdf.errors import FPDFException


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Triage statique de fichiers suspects"
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--samples", help="Dossier des échantillons")
    source.add_argument("-f", "--file", help="Un seul échantillon")

    parser.add_argument(
        "--rules",
        default="rules",
        help="Fichier ou dossier de règles YARA",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Dossier de sortie",
    )
    parser.add_argument(
        "--llm",
        choices=["offline", "openrouter", "ollama"],
        default="offline",
    )

    args = parser.parse_args(argv)

    if args.samples:
        dossier = Path(args.samples)

        if not dossier.is_dir():
            logger.error("Dossier introuvable : %s", dossier)
            return 1

        # Ces deux fichiers servent à décrire le pack.
        fichiers = sorted(
            fichier
            for fichier in dossier.iterdir()
            if fichier.is_file()
            and fichier.name not in {"GROUP.txt", "README.md"}
            and not fichier.name.endswith((
                ".triage.json",
                ".triage.pdf",
            ))
        )

    else:
        fichier = Path(args.file)

        if not fichier.is_file():
            logger.error("Fichier introuvable : %s", fichier)
            return 1

        fichiers = [fichier]

    if not fichiers:
        logger.error("Aucun échantillon à analyser")
        return 1

    if args.out is not None:
        sortie = Path(args.out)
    elif args.file:
        sortie = Path(args.file).parent
    else:
        sortie = Path("reports/tp2")

    try:
        sortie.mkdir(parents=True, exist_ok=True)
    except OSError as erreur:
        logger.error(
            "Création du dossier de sortie impossible : %s",
            erreur,
        )
        return 1

    erreurs = 0

    for fichier in fichiers:
        try:
            triage = Triage(
                str(fichier),
                args.llm,
                args.rules,
            )

            resultat = triage.run()
            destination = sortie / f"{fichier.name}.triage.json"

            report = Report(resultat)
            report.generate_json(str(destination))
            report.generate_pdf(str(destination.with_suffix(".pdf")))

            logger.info("Rapport écrit : %s", destination)

        except (OSError, ValueError, yara.Error, FPDFException) as erreur:
            erreurs += 1
            logger.error(
                "Échec pour %s : %s",
                fichier,
                erreur,
            )


    logger.info(
        "Terminé : %s fichier(s) analysé(s), %s erreur(s)",
        len(fichiers) - erreurs,
        erreurs,
    )

    return 1 if erreurs else 0

if __name__ == "__main__":
    raise SystemExit(main())
