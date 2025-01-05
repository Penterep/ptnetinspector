import csv
from src.device.node import Node

class LLMNR(Node):
    def __init__(self, mac:str, ip:str):
        # Assign to self object
        super().__init__(
            mac, ip
        )
        
    def save_LLMNR(self):
        # Function to save LLMNR IP address to a CSV file
        with open('src/tmp/LLMNR.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
    def get_llmnr_from_csv(cls):
        # Importing the information about nodes from tmp files
        with open ("src/tmp/LLMNR.csv", "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                LLMNR(
                    mac = node.get('MAC'),
                    ip = node.get('IP')
                )
    
    @staticmethod
    def full_name_llmnr(name):
        # Completing LLMNR name to ask for IP
        if name.endswith('.local.'):
            return name[:-6]
        else:
            return name

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"


