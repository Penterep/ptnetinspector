import csv
from ptnetinspector.utils.path import get_csv_path


class EAP:

    all_nodes = []
    
    def __init__(self, mac: str, packet: str):
        # Assign to self object
        self.mac = mac
        self.packet = packet
        
    def save_eap(self):
        # Function to save EAP to a CSV file
        csv_file = get_csv_path("eap.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['packet'] == self.packet:
                    return  # Record already exists in the file 
                
            fieldnames = ['MAC', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'packet': self.packet
            })

    @classmethod
    def get_eap_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("eap.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                EAP(
                    mac=node.get('MAC'),
                    packet=node.get('packet')
                )

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.packet})"