import csv

class DHCP:
    
    all_nodes = []
    def __init__(self, mac:str, ip:str):
        # Assign to self object
        self.mac = mac
        self.ip = ip
        DHCP.all_nodes.append(self)
    
    @classmethod
    def get_from_csv(cls):
        # Importing the information about nodes from tmp files
        with open ("src/tmp/dhcp.csv", "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                DHCP(
                    mac = node.get('MAC'),
                    ip = node.get('IP')
                )

    def save_addresses(self):
        # Exporting addresses to csv files and avoid duplication
        with open('src/tmp/dhcp.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip:
                    return  # Record already exists in the file 
                   
            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac
            })
             
    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"

