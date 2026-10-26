# Tests du TP1 — analyse du trafic réseau

Depuis la racine du projet, après installation des dépendances :

```bash
poetry run python -m pytest tests/tp1 -v -rx
```

Pour exécuter tous les tests du projet (TP1 et TP3) :

```bash
poetry run python -m pytest -q
```

Les tests ne nécessitent ni interface réseau, ni droits administrateur, ni accès
Internet. Les paquets Scapy sont construits en mémoire. Les tests de lecture PCAP
écrivent puis relisent de vrais fichiers temporaires. Matplotlib utilise le moteur
Agg, sans fenêtre. Les fichiers produits sont isolés dans les dossiers temporaires
de pytest et ne remplacent pas les rapports du projet.

## Couverture

- Capture : lecture d'un PCAP, fichier vide, fichier absent et format invalide.
- Statistiques : couches Ethernet, ARP, TCP, UDP, ICMP, mélange de protocoles,
  paquets inconnus, résultats stables lors d'appels répétés.
- Détection : motifs SQL et casse, adresse source, réponses ARP non sollicitées,
  adresses IP/MAC, trafic normal et scénarios sans scan SYN.
- Rapport : véritable génération PNG/PDF, signature et fin de fichier PDF,
  appels de rendu du tableau avec chaque volume et insertion du graphique.
- Fonctions utilitaires et classe Report : initialisation, concaténation,
  écriture, erreurs de fichier, graphique et paramètre inconnu.

Les tests PDF vérifient les données envoyées au moteur de rendu et la production
d'un fichier PDF ; ils ne constituent pas une vérification visuelle de la mise en page.
La capture live étant encore en développement, elle n'est pas testée ici.

## Exigences restant à implémenter

Les marqueurs `xfail(strict=True, raises=AssertionError)` rendent visibles les
écarts connus sans les présenter comme des tests réussis. Une exception inattendue
reste un échec. Si la fonction est corrigée, un résultat XPASS fait échouer la suite :
retirer alors le marqueur correspondant pour conserver le test de régression.

`utils/test_requirements.py` couvre les écarts suivants : chemin PCAP ignoré,
comptage IP/DNS/HTTP absent, réponse ARP sollicitée signalée à tort, associations
IP/MAC contradictoires non détectées dans les requêtes, scan SYN absent, SQL encodé
non détecté, fausse alerte SQL hors HTTP et alertes perdues dans le résumé.
Le scénario de scan envoie 1 000 SYN vers des ports distincts d'une même destination
en une seconde ; les seuils exacts restent à définir dans l'implémentation.

`utils/test_report.py` signale également le chemin du graphique effacé, le tableau
vide et l'argument de destination ignoré par `Report.save`.

Pour travailler uniquement sur les exigences manquantes, en les traitant comme
des échecs ordinaires pendant leur implémentation :

```bash
poetry run python -m pytest tests/tp1/utils/test_requirements.py --runxfail -v
```
