from tp1.utils.lib import choose_interface, hello_world


def test_hello_world():
    assert hello_world() == "hello world"


def test_choose_interface():
    assert choose_interface() == "en0"
