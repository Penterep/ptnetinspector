import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node


class MLDv1(Node):
    def __init__(self, mac: str, ip: str, protocol: str, mulip: str):
        # Assign to self object
        super().__init__(mac, ip)
        self.protocol = protocol
        self.mulip = mulip
        
    def save_MLDv1(self):
        # Function to save MLDv1 information to a CSV file
        csv_file = get_csv_path("MLDv1.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip and row['protocol'] == self.protocol and row['mulip'] == self.mulip:
                    return  # Record already exists in the file
                
            fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'protocol': self.protocol,
                'mulip': self.mulip
            })
    
    @classmethod
    def get_mldv1_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("MLDv1.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                MLDv1(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    protocol=node.get('protocol'),
                    mulip=node.get('mulip')
                )
    
    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.mulip})"