import csv
from ptnetinspector.utils.path import get_csv_path


class DHCP:
    
    all_nodes = []
    
    def __init__(self, mac: str, ip: str, role: str):
        # Assign to self object
        self.mac = mac
        self.ip = ip
        self.role = role
        DHCP.all_nodes.append(self)
    
    @classmethod
    def get_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("dhcp.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                DHCP(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    role=node.get('Role')
                )

    def save_addresses(self):
        # Exporting addresses to csv files and avoid duplication
        csv_file = get_csv_path("dhcp.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip and row['Role'] == self.role:
                    return  # Record already exists in the file 
                   
            fieldnames = ['MAC', 'IP', 'Role']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac,
                'Role': self.role
            })
             
    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"