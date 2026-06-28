
from dataclasses import dataclass

@dataclass
class AttackEdge:
    source:str
    target:str
    relation:str

class AttackGraph:
    def __init__(self):
        self.nodes=set()
        self.edges=[]

    def add_node(self,node):
        self.nodes.add(node)

    def add_edge(self,source,target,relation):
        self.nodes.add(source)
        self.nodes.add(target)
        self.edges.append(AttackEdge(source,target,relation))
