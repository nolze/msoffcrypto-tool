from abc import ABC
from abc import abstractmethod

class BaseOfficeFile(ABC):
    def __init__(self):
        pass
    
    @abstractmethod
    def load_key(self):
        pass

    @abstractmethod
    def decrypt(self):
        pass
