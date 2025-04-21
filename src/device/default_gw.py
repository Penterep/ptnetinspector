import csv


class DefaultGateway:
    all_nodes = []

    def __init__(self, mac: str, ip: str):
        self.mac = mac
        self.ip = ip
        DefaultGateway.all_nodes.append(self)

    def save_addresses(self):
        with open('src/tmp/default_gw.csv', 'a+', newline='') as csvfile:
            csvfile.seek(0)
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip:
                    return

            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac
            })

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"

