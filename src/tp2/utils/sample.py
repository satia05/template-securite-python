import math
from collections import Counter
import hashlib
import magic
import ipaddress
import re

from urllib.parse import urlsplit

import lief
from tp2.utils.config import logger


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""

        metadata = {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": magic.from_buffer(self.data),
            "entropy": self.shannon_entropy(),
        }

        return metadata

        raise NotImplementedError

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""

        """Extraire les indicateurs présents dans les chaînes du fichier."""
        chaines = []

        # Chaînes ASCII.
        for chaine in re.findall(rb"[\x20-\x7e]{4,}", self.data):
            chaines.append(chaine.decode("ascii"))

        # Chaînes UTF-16, fréquentes dans les programmes Windows.
        for chaine in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", self.data):
            chaines.append(chaine.decode("utf-16-le"))

        # Ces lignes sont des consignes pour IA, pas des indications fiables.
        lignes = []
        for chaine in chaines:
            if not re.match(
                    r"^\s*(AI_INSTRUCTIONS|NOTE_TO_AI|SYSTEM PROMPT|X-AI-Instructions)\s*:",
                    chaine,
                    re.IGNORECASE,
            ):
                lignes.append(chaine)

        texte = "\n".join(lignes)

        urls = set()
        for url in re.findall(r"https?://[^\s<>\"']+", texte, re.IGNORECASE):
            urls.add(url.rstrip(".,;)"))

        ips = set()
        for adresse in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texte):
            try:
                ipaddress.IPv4Address(adresse)
                ips.add(adresse)
            except ValueError:
                continue

        domaines = set()
        extensions = {
            "dll", "exe", "bin", "so", "dylib", "pdb",
            "txt", "pdf", "json", "png", "jpg",
            "php", "html", "htm", "js", "css",
        }

        for domaine in re.findall(
                r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
                texte,
        ):
            domaine = domaine.lower()

            # Éviter de prendre cmd.exe ou urlmon.dll pour des domaines.
            if domaine.rsplit(".", 1)[-1] not in extensions:
                domaines.add(domaine)

        # Le nom d'hôte d'une URL est aussi un indicateur.
        for url in urls:
            hote = urlsplit(url).hostname
            if hote:
                try:
                    ipaddress.ip_address(hote)
                except ValueError:
                    domaines.add(hote.lower())

        mutex = set()
        for valeur in re.findall(
                r"\b(?:Global|Local)\\+[a-zA-Z0-9_.{}-]+",
                texte,
        ):
            mutex.add(re.sub(r"\\+", lambda match: "\\", valeur))

        registry = set()
        for valeur in re.findall(
                r"\b(?:HKCU|HKLM|HKCR|HKU|HKCC|HKEY_CURRENT_USER|"
                r"HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS|"
                r"HKEY_CURRENT_CONFIG)\\+[^\r\n\"<>]+",
                texte,
        ):
            registry.add(re.sub(r"\\+", lambda match: "\\", valeur))

        chemins = set(
            re.findall(r"\b[a-zA-Z]:\\[^\r\n\"<>|]+", texte)
        )
        chemins.update(
            re.findall(
                r"(?<![:/\w])/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+",
                texte,
            )
        )

        return {
            "domains": sorted(domaines),
            "ips": sorted(ips),
            "urls": sorted(urls),
            "mutex": sorted(mutex),
            "registry": sorted(registry),
            "paths": sorted(chemins),
        }
        raise NotImplementedError

    def extract_flag(self) -> str | None:
        """Lire un champ FLAG explicite sans suivre les notes du fichier."""
        chaines = [
            chaine.decode("ascii")
            for chaine in re.findall(rb"[\x20-\x7e]{4,}", self.data)
        ]

        chaines += [
            chaine.decode("utf-16-le")
            for chaine in re.findall(
                rb"(?:[\x20-\x7e]\x00){4,}",
                self.data,
            )
        ]

        flags = set()

        for chaine in chaines:
            correspondance = re.fullmatch(
                r"FLAG\s*=\s*(ESGI\{[A-Za-z0-9_-]+\})",
                chaine.strip(),
            )

            if correspondance:
                flags.add(correspondance.group(1))

        if len(flags) == 1:
            return flags.pop()

        if len(flags) > 1:
            logger.warning(
                "Plusieurs champs FLAG différents : %s",
                self.path,
            )

        return None


    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        resultat = {
            "imports": [],
            "sections": [],
            "exports": [],
        }

        # MZ correspond aux fichiers PE ; ELF possède une autre signature.
        if not self.data.startswith((b"MZ", b"\x7fELF")):
            logger.info("Le fichier n'est pas un PE ou un ELF : %s", self.path)
            return resultat

        try:
            binaire = lief.parse(self.path)

            if binaire is None:
                logger.warning("Structure du binaire illisible : %s", self.path)
                return resultat

            resultat["imports"] = sorted({
                fonction.name
                for fonction in binaire.imported_functions
                if fonction.name
            })

            resultat["exports"] = sorted({
                fonction.name
                for fonction in binaire.exported_functions
                if fonction.name
            })

            for section in binaire.sections:
                resultat["sections"].append({
                    "name": section.name,
                    "size": section.size,
                })


        except (OSError, RuntimeError, ValueError) as erreur:
            logger.warning(
                "Analyse du binaire impossible pour %s : %s",
                self.path,
                erreur,
            )

        return resultat



        raise NotImplementedError


