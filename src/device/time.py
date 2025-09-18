import csv

class Time:

    all_nodes = []
    def __init__(self, time:str, MAC:str, packet:str):
        # Assign to self object
        self.time = time
        self.MAC = MAC
        self.packet = packet
        Time.all_nodes.append(self)
        
    def save_time(self):
        # Function to save time and packet to a CSV file
        with open('src/tmp/time_all.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
        with open('src/tmp/time_incoming.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
        with open('src/tmp/time_outgoing.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
        with open('src/tmp/start_end_mode.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': time
            })


    def __repr__(self):
        return f"{self.__class__.__name__}({self.time}, {self.packet})"


