from abc import ABC, abstractmethod

# Base class for all defense layers
# Each defense layer should inherit from this class and implement the process method
class DefenseLayer(ABC):

    # constructor to initialize the layer with a name and an enabled flag
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

# abstract method that does the defence processing
    @abstractmethod
    def process(self,text):
        pass
        

# string representation of the layer for debugging purposes
    def __repr__(self):
        return f"{self.name}(enabled={self.enabled})"