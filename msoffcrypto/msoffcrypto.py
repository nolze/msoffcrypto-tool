import olefile

def OfficeFile(file):
    ole = olefile.OleFileIO(file)
    
    ## MS-DOC: The WordDocument stream MUST be present in the file.
    ## https://msdn.microsoft.com/en-us/library/dd926131(v=office.12).aspx
    if ole.exists('wordDocument'):
        from .format.doc97 import Doc97File
        return Doc97File(file)
    elif ole.exists('EncryptionInfo'):
        from .format.ooxml import OOXMLFile
        return OOXMLFile(file)
    else:
        raise AssertionError("Unrecognized file format")
