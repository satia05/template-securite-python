"""Exigences non satisfaites : XFAIL documentés, stricts et limités aux assertions.

Un XPASS fait échouer la suite : après correction de la fonction, retirer son marqueur.
"""

from pathlib import Path

import pytest
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw
from scapy.layers.http import HTTP, HTTPRequest
from tp1.utils.capture import Capture


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Capture.__init__ ignore le chemin PCAP fourni")
def test_constructor_keeps_requested_pcap(tmp_path):
    path = tmp_path / "custom.pcap"
    assert Path(Capture(str(path)).pcap_file) == path


@pytest.mark.parametrize("protocol, packet", [
    ("IP", Ether() / IP() / TCP()),
    ("DNS", Ether() / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="example.test"))),
    ("HTTP", Ether() / IP() / TCP(dport=80) / HTTP() / HTTPRequest()),
])
@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Le comptage ne couvre pas encore IP, DNS et HTTP")
def test_required_protocol_counts(capture, protocol, packet):
    capture.packet = [packet]
    assert capture.sort_network_protocols().get(protocol) == 1


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Toutes les réponses ARP sont signalées, même sollicitées")
def test_solicited_arp_reply_is_not_an_attack(analyse_packets):
    output = analyse_packets([
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, psrc="192.0.2.1", pdst="192.0.2.2", hwsrc="02:00:00:00:00:01"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") /
        ARP(op=2, psrc="192.0.2.2", pdst="192.0.2.1",
            hwsrc="02:00:00:00:00:02", hwdst="02:00:00:00:00:01"),
    ])
    assert "ARP suspect" not in output


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Absence de détection des associations IP/MAC contradictoires")
def test_conflicting_arp_mappings_in_requests(analyse_packets):
    output = analyse_packets([
        Ether(src=mac) / ARP(op=1, psrc="192.0.2.10", pdst="192.0.2.1", hwsrc=mac)
        for mac in ["02:00:00:00:00:10", "02:00:00:00:00:11"]
    ])
    assert "ARP" in output
    assert "192.0.2.10" in output
    assert "02:00:00:00:00:11" in output


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="La détection des scans de ports SYN reste à implémenter")
def test_syn_port_scan_identifies_attacker(analyse_packets):
    packets = [
        IP(src="192.0.2.30", dst="192.0.2.1") / TCP(dport=port, flags="S")
        for port in range(1, 1001)
    ]
    for index, packet in enumerate(packets):
        packet.time = 1700000000 + index / 1000
    output = analyse_packets(packets)
    assert "scan" in output.lower()
    assert "192.0.2.30" in output


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Les paramètres HTTP encodés ne sont pas décodés")
def test_url_encoded_sql_injection(analyse_packets):
    output = analyse_packets([
        IP(src="192.0.2.40") / TCP(dport=80) /
        Raw(b"GET /?id=%27%20OR%201%3D1 HTTP/1.1\r\n\r\n")
    ])
    assert "injection SQL" in output
    assert "192.0.2.40" in output


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="La recherche SQL porte sur tout Raw, sans vérifier HTTP")
def test_non_http_payload_is_not_http_sql_injection(analyse_packets):
    output = analyse_packets([IP() / UDP(dport=9999) / Raw(b"union select")])
    assert "injection SQL" not in output


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="Le résumé perd les alertes et ne conserve que le chemin PDF")
def test_summary_retains_attack_details(capture, analyse_packets):
    analyse_packets([IP(src="192.0.2.50") / TCP(dport=80) / Raw(b"GET /?id=' OR 1=1 HTTP/1.1\r\n\r\n")])
    assert "injection SQL" in capture.get_summary()
    assert "192.0.2.50" in capture.get_summary()
