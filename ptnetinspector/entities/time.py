import csv
from ptnetinspector.utils.path import get_csv_path


class Time:

    all_nodes = []
    
    def __init__(self, time: str, MAC: str, packet: str):
        # Assign to self object
        self.time = time
        self.MAC = MAC
        self.packet = packet
        Time.all_nodes.append(self)
        
    def save_time(self):
        # Function to save time and packet to a CSV file
        csv_file = get_csv_path("time_all.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time', 'MAC', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': self.time,
                'MAC': self.MAC,
                'packet': self.packet
            })
    
    def save_time_incoming(self):
        # Function to save time and packet to a CSV file
        csv_file = get_csv_path("time_incoming.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time', 'MAC', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': self.time,
                'MAC': self.MAC,
                'packet': self.packet
            })
    
    def save_time_outgoing(self):
        # Function to save time and packet to a CSV file
        csv_file = get_csv_path("time_outgoing.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time', 'MAC', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': self.time,
                'MAC': self.MAC,
                'packet': self.packet
            })
    
    @staticmethod
    def save_start_end(time):
        # Function to save time and packet to a CSV file
        csv_file = get_csv_path("start_end_mode.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': time
            })

    def __repr__(self):
        return f"{self.__class__.__name__}({self.time}, {self.packet})"