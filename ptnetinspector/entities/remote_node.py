import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node


class Remote_node(Node):
    all_nodes = []
    
    def __init__(self, smac: str, sip: str, dmac: str, dip: str):
        # Assign to self object
        self.smac = smac
        self.sip = sip
        self.dmac = dmac
        self.dip = dip
        Remote_node.all_nodes.append(self)
    
    @classmethod
    def get_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("remote_node.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                Remote_node(
                    smac=node.get('src MAC'),
                    sip=node.get('src IP'),
                    dmac=node.get('dst MAC'),
                    dip=node.get('dst IP')
                )

    def save_remote_node(self):
        # Exporting addresses to csv files and avoid duplication
        csv_file = get_csv_path("remote_node.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['src MAC'] == self.smac and row['src IP'] == self.sip and row['dst MAC'] == self.dmac and row['dst IP'] == self.dip:
                    return  # Record already exists in the file 
                   
            fieldnames = ['src MAC', 'dst MAC', 'src IP', 'dst IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'src MAC': self.smac,
                'src IP': self.sip,
                'dst MAC': self.dmac,
                'dst IP': self.dip
            })
           
    def __repr__(self):
        return f"{self.__class__.__name__}({self.smac}, {self.sip}, {self.dmac}, {self.dip})"