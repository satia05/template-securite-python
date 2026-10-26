"""Tests des fonctions implémentées, à partir de paquets Scapy synthétiques."""

from unittest.mock import patch

import pytest
from PIL import Image
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap
from tp1.utils import capture as capture_module


ZERO_COUNTS = {"Ethernet": 0, "ARP": 0, "TCP": 0, "UDP": 0, "ICMP": 0}


def test_capture_init(capture):
    assert capture.packet == []
    assert capture.get_summary() == ""


def test_read_pcap(capture, tmp_path):
    path = tmp_path / "traffic.pcap"
    packets = [Ether() / IP() / TCP(dport=80), Ether() / ARP()]
    wrpcap(str(path), packets)
    # Le chemin fourni au constructeur est actuellement ignoré (test dédié).
    capture.pcap_file = path
    capture.capture_traffic()
    assert [bytes(p) for p in capture.packet] == [bytes(p) for p in packets]


def test_read_pcap_replaces_previous_packets(capture, tmp_path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])
    capture.pcap_file = path
    capture.packet = [Ether() / ARP()]
    capture.capture_traffic()
    assert len(capture.packet) == 0


def test_missing_pcap(capture, tmp_path):
    capture.pcap_file = tmp_path / "missing.pcap"
    with pytest.raises(FileNotFoundError):
        capture.capture_traffic()


def test_invalid_pcap(capture, tmp_path):
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"this is not a PCAP file")
    capture.pcap_file = path
    with pytest.raises(capture_module.Scapy_Exception):
        capture.capture_traffic()


def test_empty_protocol_counts(capture):
    assert capture.sort_network_protocols() == ZERO_COUNTS


@pytest.mark.parametrize("packet, names", [
    (Ether() / ARP(), ["Ethernet", "ARP"]),
    (Ether() / IP() / TCP(), ["Ethernet", "TCP"]),
    (Ether() / IP() / UDP(), ["Ethernet", "UDP"]),
    (Ether() / IP() / ICMP(), ["Ethernet", "ICMP"]),
    (IP() / TCP(), ["TCP"]),
    (Raw(b"unknown"), []),
])
def test_protocol_layers(capture, packet, names):
    capture.packet = [packet]
    expected = dict(ZERO_COUNTS)
    expected.update({name: 1 for name in names})
    assert capture.sort_network_protocols() == expected


def test_mixed_protocol_counts_are_repeatable(capture):
    capture.packet = [
        Ether() / ARP(), Ether() / IP() / TCP(), Ether() / IP() / TCP(),
        Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.test")),
        Ether() / IP() / ICMP(),
    ]
    expected = {"Ethernet": 5, "ARP": 1, "TCP": 2, "UDP": 1, "ICMP": 1}
    assert capture.sort_network_protocols() == expected
    assert capture.sort_network_protocols() == expected
    assert len(capture.packet) == 5


@pytest.mark.parametrize("payload", [
    b"GET /?id=' OR 1=1 HTTP/1.1\r\n\r\n",
    b"GET /?id=1 UNION SELECT password HTTP/1.1\r\n\r\n",
    b"GET /?id=1 UnIoN SeLeCt password HTTP/1.1\r\n\r\n",
])
def test_sql_injection_identifies_source(analyse_packets, payload):
    output = analyse_packets([IP(src="192.0.2.10") / TCP(dport=80) / Raw(payload)])
    assert "injection SQL" in output
    assert "192.0.2.10" in output


@pytest.mark.parametrize("packet", [
    IP() / TCP(dport=80) / Raw(b"GET /index.html HTTP/1.1\r\n\r\n"),
    IP() / TCP(flags="A"), Ether() / ARP(op=1),
])
def test_normal_traffic_has_no_alert(analyse_packets, packet):
    output = analyse_packets([packet])
    assert "injection SQL" not in output
    assert "ARP suspect" not in output


def test_unsolicited_arp_reply_identifies_ip_and_mac(analyse_packets):
    output = analyse_packets([
        Ether() / ARP(op=2, psrc="192.0.2.20", hwsrc="02:00:00:00:00:20")
    ])
    assert "ARP suspect" in output
    assert "192.0.2.20" in output
    assert "02:00:00:00:00:20" in output


def test_analyse_updates_summary(capture):
    with patch.object(capture, "_gen_summary", return_value="rapport.pdf") as generate:
        assert capture.analyse() == "rapport.pdf"
    generate.assert_called_once_with()
    assert capture.get_summary() == "rapport.pdf"


def test_get_summary(capture):
    capture.summary = "Résumé de test"
    assert capture.get_summary() == "Résumé de test"


@pytest.mark.parametrize("with_packets", [False, True])
def test_summary_creates_pdf_with_table_and_graph(capture, tmp_path, with_packets):
    if with_packets:
        capture.packet = [Ether() / IP() / TCP(), Ether() / ARP()]
    real_pdf = capture_module.canvas.Canvas(str(tmp_path / "rapport.pdf"))
    with patch.object(capture_module.canvas, "Canvas", return_value=real_pdf), \
         patch.object(real_pdf, "drawString", wraps=real_pdf.drawString) as text, \
         patch.object(real_pdf, "drawImage", wraps=real_pdf.drawImage) as image:
        result = capture._gen_summary()
    assert result == "rapport.pdf"
    data = (tmp_path / result).read_bytes()
    assert data.startswith(b"%PDF-")
    assert data.rstrip().endswith(b"%%EOF")
    labels = [call.args[2] for call in text.call_args_list]
    assert "Rapport du trafic réseau" in labels
    assert "Protocole" in labels
    assert "Nombre de paquets" in labels
    rows = [(call.args[1], call.args[2]) for call in text.call_args_list]
    for index, (name, count) in enumerate(capture.sort_network_protocols().items()):
        y = 735 - 20 * index
        assert (y, name) in rows
        assert (y, str(count)) in rows
    assert image.call_count >= 1
    assert all(call.args[0] == "protocoles.png" for call in image.call_args_list)
    with Image.open(tmp_path / "protocoles.png") as chart:
        assert chart.format == "PNG"
        assert chart.width > 0 and chart.height > 0
        chart.verify()


@pytest.mark.parametrize("packets", [
    [IP(src="192.0.2.30") / TCP(dport=443, flags="S") for _ in range(100)],
    [IP(src=f"192.0.2.{i}") / TCP(dport=i, flags="S") for i in range(1, 101)],
    [IP(src="192.0.2.30") / TCP(dport=i, flags="A") for i in range(1, 101)],
])
def test_traffic_without_syn_scan_has_no_scan_alert(analyse_packets, packets):
    assert "scan" not in analyse_packets(packets).lower()
