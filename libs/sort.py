import csv

def sort(input_file, output_file):
    """
    Description:
        Reads a CSV file containing 'src MAC' and 'source IP' columns,
        maps each MAC address to its associated IP addresses,
        and writes the results to an output CSV file with columns 'MAC' and 'IP'.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output CSV file.

    Output:
        Writes a CSV file with columns 'MAC' and 'IP', listing each MAC address
        and its associated IP addresses.
    """
    mac_to_ips = {}

    with open(input_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            mac = row['src MAC']
            ip = row['source IP']
            if mac not in mac_to_ips:
                mac_to_ips[mac] = set()
            mac_to_ips[mac].add(ip)

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['MAC', 'IP'])
        for mac, ips in mac_to_ips.items():
            for ip in ips:
                writer.writerow([mac, ip])
