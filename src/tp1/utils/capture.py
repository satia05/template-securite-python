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
        self.packet = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from a PCAP file
        """




    def sort_network_protocols(self) -> dict[str, int]:
        """
        Sort and return all captured network protocols
        """


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






