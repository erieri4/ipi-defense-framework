from src.layers.base import DefenseLayer

class DefensePipeline:

    def __init__(self, layers: list[DefenseLayer]):
        self.layers = layers



    # method to process the input text through all enabled layers in the pipeline

    def run (self,text: str) -> str:
        for layer in self.layers:
            if layer.enabled:
                text = layer.process(text)
        return text
