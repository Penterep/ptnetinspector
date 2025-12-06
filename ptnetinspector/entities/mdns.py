import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node


class MDNS(Node):
    def __init__(self, mac: str, ip: str):
        # Assign to self object
        super().__init__(mac, ip)
        
    def save_MDNS(self):
        # Function to save MDNS IP address to a CSV file
        csv_file = get_csv_path("MDNS.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip:
                    return  # Record already exists in the file
                
            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip
            })

    @classmethod
    def get_MDNS_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("MDNS.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                MDNS(
                    mac=node.get('MAC'),
                    ip=node.get('IP')
                )
    
    @staticmethod
    def full_name_MDNS(name):
        # Function to complete MDNS name to use for asking about IP
        if ".local" in name:
            return name
        else:
            return name + ".local"

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"