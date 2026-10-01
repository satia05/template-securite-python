from csv import Sniffer
from itertools import count
from unittest import result

from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

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

        sort = self.sort_network_protocols()
        logger.info(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

        return self.summary


    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """

    def _gen_summary(self) -> str:
        """
        Generate summary
        """

        summary = ""
        return summary


if __name__ == "__main__":
    capture = Capture("capture.pcap")
    capture.capture_traffic()
    capture.analyse()



