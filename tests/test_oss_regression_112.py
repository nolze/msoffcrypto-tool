import io
from pathlib import Path
from xml.parsers.expat import ExpatError

import pytest

from msoffcrypto import OfficeFile, exceptions


def test_officefile_truncated_agile_xml_raises_parse_error():
    data = (Path(__file__).parent / "inputs" / "example_password.xlsx").read_bytes()

    with pytest.raises((exceptions.ParseError, ExpatError)) as error:
        OfficeFile(io.BytesIO(data[:-256]))

    assert isinstance(error.value, exceptions.ParseError), (
        "Malformed agile EncryptionInfo XML must raise ParseError"
    )
    assert isinstance(error.value.__cause__, ExpatError)
