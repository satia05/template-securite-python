from pathlib import Path

import yara

from tp2.utils.config import logger

class YaraScanner:
    def __init__(self, rules_path: str = "rules") -> None:
        self.rules_path = rules_path
        chemin = Path(rules_path)
        if chemin.is_file():
            self.rules = yara.compile(filepath=str(chemin))

        elif chemin.is_dir():
            fichiers = sorted(
                fichier
                for fichier in chemin.rglob("*")
                if fichier.is_file()
                and fichier.suffix.lower() in {".yar", ".yara", ".txt"}
            )

            if not fichiers:
                raise FileNotFoundError("Aucune règle YARA trouvée")

            sources = {}
            for numero, fichier in enumerate(fichiers):
                sources[f"fichier_{numero}"] = str(fichier)

            self.rules = yara.compile(filepaths=sources)

        else:
            raise FileNotFoundError(
                f"Chemin des règles introuvable : {rules_path}"
            )

        logger.info("Règles YARA chargées depuis : %s", rules_path)


    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""

        correspondances = self.rules.match(data=data, timeout=5)

        noms = sorted({
            correspondances.rule
            for correspondances in correspondances
        })

        logger.info("Résultat de YARA: %s", noms)

        return noms

        raise NotImplementedError
