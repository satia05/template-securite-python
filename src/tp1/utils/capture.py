from csv import Sniffer
from itertools import count
from unittest import result

from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import Ether, ARP

import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas

from tp1.utils.config import logger
from pathlib import Path
import os


class Capture:
    def __init__(self, pcap_file: str) -> None:
        self.pcap_file = pcap_file
        self.pcap_file = Path(__file__).parent.parent / "capture.pcap"
        self.packet = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from a PCAP file
        """

        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        sniff(iface=self.interface,
              prn=self.capture_traffic,
              count=5
              )
        """

        logger.info(f"Reading PCAP file: {self.pcap_file}")

        self.packet = rdpcap(str(self.pcap_file))


    def sort_network_protocols(self) -> dict[str, int]:
        """
        Sort and return all captured network protocols
        """

        protocols = {
            "Ethernet": 0,
            "ARP": 0,
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
        }


        # boucle qui cherche les protocoles dans le packet et qui les ajoutes 1 par 1
        for p in self.packet:

            if p.haslayer(Ether):
                protocols["Ethernet"] += 1

            if p.haslayer(ARP):
                protocols["ARP"] += 1

            if p.haslayer(TCP):
                protocols["TCP"] += 1

            if p.haslayer(UDP):
                protocols["UDP"] += 1

            if p.haslayer(ICMP):
                protocols["ICMP"] += 1

        return protocols


    def analyse(self) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """

        result = ""

        for packet in self.packet:

            #SQL
            if packet.haslayer(Raw):
                data = str(packet[Raw].load).lower()

                if "union select" in data or "or 1=1" in data:
                    result += " - Tentative injection SQL"

                    if packet.haslayer(IP):
                        result += " - IP : " + packet[IP].src

                    result += "\n"

            #ARP
            if packet.haslayer(ARP):
                if packet[ARP].op == 2:
                    result += " - ARP suspect : " + packet[ARP].psrc + " - MAC :" + packet[ARP].hwsrc + "\n"
                    self.summary += result

        #log des attaques réseaux
        logger.info(result)
        print(result)

        #trie de tout les protocoles
        sort = self.sort_network_protocols()
        logger.info(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

        return self.summary

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """

        return self.summary


    def _gen_summary(self) -> str:
        """
        Generate summary
        """

        protocols = self.sort_network_protocols()

        nom = list(protocols.keys())
        val = list(protocols.values())

        plt.bar(nom, val)                   # Créer les bars
        plt.title("Volume des protocoles")
        plt.xlabel("Protocoles")            # Donne le nom pour l'axe x
        plt.ylabel("Nombre de paquets")     # Donne le nom pour l'axe y

        plt.savefig("protocoles.png")
        plt.close()

        # PDF
        pdf = canvas.Canvas("rapport.pdf")

        pdf.drawString(50, 800, "Rapport du trafic réseau")

        # Titre du tableau
        pdf.drawString(50, 760, "Protocole")
        pdf.drawString(200, 760, "Nombre de paquets")

        y = 735

        # Tableau
        for protocol in protocols:
            pdf.drawString(50, y, protocol)
            pdf.drawString(200, y, str(protocols[protocol]))

            y -= 20

        # Graphique
            pdf.drawImage(
    "protocoles.png",
        50,
        300,
        width=500,
        height=300
        )

        pdf.save()


        return "rapport.pdf"

if __name__ == "__main__":
    capture = Capture("capture.pcap")
    capture.capture_traffic()
    capture.analyse()




