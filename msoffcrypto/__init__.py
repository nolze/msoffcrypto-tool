import olefile


__version__ = "4.6.4"


def OfficeFile(file):
    '''Return an office file object based on the format of given file.

    Args:
        file (:obj:`_io.BufferedReader`): Input file.

    Returns:
        BaseOfficeFile object.

    Examples:
        >>> f = open("tests/inputs/example_password.docx", "rb")
        >>> officefile = OfficeFile(f)
        >>> officefile.keyTypes
        ('password', 'private_key', 'secret_key')
    '''
    ole = olefile.OleFileIO(file)

    # TODO: Make format specifiable by option in case of obstruction
    # Try this first; see https://github.com/nolze/msoffcrypto-tool/issues/17
    if ole.exists('EncryptionInfo'):
        from .format.ooxml import OOXMLFile
        return OOXMLFile(file)
    # MS-DOC: The WordDocument stream MUST be present in the file.
    # https://msdn.microsoft.com/en-us/library/dd926131(v=office.12).aspx
    elif ole.exists('wordDocument'):
        from .format.doc97 import Doc97File
        return Doc97File(file)
    # MS-XLS: A file MUST contain exactly one Workbook Stream, ...
    # https://msdn.microsoft.com/en-us/library/dd911009(v=office.12).aspx
    elif ole.exists('Workbook'):
        from .format.xls97 import Xls97File
        return Xls97File(file)
    else:
        raise Exception("Unrecognized file format")
