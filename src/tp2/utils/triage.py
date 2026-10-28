from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner

import json

class Triage:
    def __init__(
        self,
        path: str,
        backend: str = "offline",
        rules_path: str = "rules",
    ) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules_path)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(
            "Triage de %s : %s octets",
            self.path,
            len(sample.data),
        )

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)

        summary = json.dumps({
            "meta": meta,
            "iocs": iocs,
            "bin": bininfo,
            "yara": matches,
        })

        verdict = self.llm.triage(summary)

        # Le flag vient du fichier, jamais du verdict du modèle.
        flag = sample.extract_flag()

        result = {
            **meta,
            "iocs": {
                cle: iocs[cle]
                for cle in [
                    "domains",
                    "ips",
                    "urls",
                    "mutex",
                    "registry",
                ]
            },
            "imports": bininfo["imports"],
            "yara_matches": matches,
            "family_guess": verdict["family_guess"],
            "mitre_attack": verdict["mitre_attack"],
            "llm_summary": verdict["llm_summary"],
            "score": verdict["score"],
            "flag": flag,
        }

        logger.info(
            "Résultat : famille=%s, score=%s, flag=%s",
            result["family_guess"],
            result["score"],
            flag,
        )

        return result
