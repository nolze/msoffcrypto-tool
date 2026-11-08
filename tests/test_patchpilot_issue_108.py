import shutil
import io
import olefile
import pytest

from msoffcrypto import OfficeFile, exceptions

def _corrupt_xls_workbook(src_path, dst_path):
    """
    Copy an XLS file and corrupt the first record id in the Workbook stream
    (change it to 0x0000). This triggers the assert in Xls97File parsing.
    """
    shutil.copyfile(src_path, dst_path)
    # Open the OLE file in write mode and replace the first two bytes of the Workbook stream.
    with olefile.OleFileIO(dst_path, write_mode=True) as ole:
        data = ole.openstream('Workbook').read()
        # Replace the first record identifier (2 bytes, little‑endian) with 0x0000.
        corrupted = b'\x00\x00' + data[2:]
        ole.write_stream('Workbook', corrupted)

def _corrupt_ppt_current_user(src_path, dst_path):
    """
    Copy a PPT file and corrupt the recVer byte in the Current User stream.
    Changing it from 0 to 1 triggers the assert in Ppt97File parsing.
    """
    shutil.copyfile(src_path, dst_path)
    # The stream name for the Current User data in PPT97 files is "Current User".
    with olefile.OleFileIO(dst_path, write_mode=True) as ole:
        data = ole.openstream('Current User').read()
        # The first byte is recVer; change it from 0 to 1.
        corrupted = bytes([1]) + data[1:]
        ole.write_stream('Current User', corrupted)

def test_is_encrypted_malformed_xls_raises_fileformaterror(tmp_path):
    """
    Ensure that a malformed XLS (wrong first record id) raises FileFormatError.
    The bug currently raises AssertionError, causing this test to fail.
    """
    src = "tests/inputs/plain.xls"
    dst = tmp_path / "malformed.xls"
    _corrupt_xls_workbook(src, dst)
    with open(dst, "rb") as f:
        office = OfficeFile(f)
        # The correct behaviour is to raise FileFormatError (or ParseError).
        with pytest.raises(exceptions.FileFormatError):
            office.is_encrypted()

def test_is_encrypted_malformed_ppt_raises_fileformaterror(tmp_path):
    """
    Ensure that a malformed PPT (wrong recVer in Current User) raises FileFormatError.
    The bug currently raises AssertionError, causing this test to fail.
    """
    src = "tests/inputs/plain.ppt"
    dst = tmp_path / "malformed.ppt"
    _corrupt_ppt_current_user(src, dst)
    with open(dst, "rb") as f:
        office = OfficeFile(f)
        # The correct behaviour is to raise FileFormatError (or ParseError).
        with pytest.raises(exceptions.FileFormatError):
            office.is_encrypted()

