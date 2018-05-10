def OfficeFile(file):
    # TODO: Conditional on file
    from .ooxml import OOXMLFile
    return OOXMLFile(file)
