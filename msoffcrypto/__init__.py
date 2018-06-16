import olefile


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

    # MS-DOC: The WordDocument stream MUST be present in the file.
    # https://msdn.microsoft.com/en-us/library/dd926131(v=office.12).aspx
    if ole.exists('wordDocument'):
        from .format.doc97 import Doc97File
        return Doc97File(file)
    elif ole.exists('EncryptionInfo'):
        from .format.ooxml import OOXMLFile
        return OOXMLFile(file)
    else:
        raise AssertionError("Unrecognized file format")
