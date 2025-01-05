import csv

def sort(input_file, output_file):
    # Initialize an empty dictionary to map MAC addresses to IP addresses
    mac_to_ips = {}

    # Open the input CSV file for reading
    with open(input_file, 'r') as csvfile:
        # Create a CSV DictReader
        reader = csv.DictReader(csvfile)

        # Iterate over each row in the CSV file
        for row in reader:
            # Get the MAC address and the source IP address from the row
            mac = row['src MAC']
            ip = row['source IP']

            # If the MAC address is not in the dictionary, add it with an empty set as the value
            if mac not in mac_to_ips:
                mac_to_ips[mac] = set()

            # Add the IP address to the set of IP addresses for the MAC address
            mac_to_ips[mac].add(ip)

    # Open the output CSV file for writing
    with open(output_file, 'w', newline='') as csvfile:
        # Create a CSV writer
        writer = csv.writer(csvfile)

        # Write the header row to the CSV file
        writer.writerow(['MAC', 'IP'])

        # Iterate over each MAC address and set of IP addresses in the dictionary
        for mac, ips in mac_to_ips.items():
            # For each IP address in the set, write a row to the CSV file with the MAC address and the IP address
            for ip in ips:
                writer.writerow([mac, ip])
