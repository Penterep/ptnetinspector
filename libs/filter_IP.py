import csv
import ipaddress
# define a function to filter IPv4 and IPv6 addresses
def IPv4_IPv6_filter(input_filename):
    """
    Filters IPv6 addresses from a CSV file containing IP addresses.

    Args:
        input_filename (str): Path to the input CSV file. The file must have an 'IP' column.
        output_filename (str): Path to the output CSV file for filtered IPv6 addresses.

    Output:
        Writes filtered IPv6 addresses (excluding link-local, multicast, and unspecified) to output_filename.
    """
    # The filename for the output file that will contain filtered IPv6 addresses
    ipv6_output_filename = 'src/tmp/ipv6.csv'

    # Open the input file for reading and the output file for appending
    with open(input_filename, 'r') as input_file, open(ipv6_output_filename, 'a') as ipv6_output_file:
        # Create a CSV DictReader for the input file. This will allow us to access
        # data from each row in the csv as a dictionary.
        reader = csv.DictReader(input_file)

        # Create a CSV writer for the output file. This will allow us to write rows of data
        # into the output file in csv format.
        ipv6_writer = csv.writer(ipv6_output_file)

    # Loop over each row in the input file
        for row in reader:
            # Get the IP address string from the 'IP' field of the row
            ip_str = row['IP']

            # Try to create an ip_address object from the IP string.
            # This may raise a ValueError if the IP string is not a valid IP address.
            try:
                ip = ipaddress.ip_address(ip_str)

                # If the IP address is version 4, do nothing and continue to the next row.
                if ip.version == 4:
                    pass
                # If the IP address is version 6, check if it's link-local, multicast, or unspecified
                elif ip.version == 6:
                    # If the IP address is not link-local, not multicast, and not unspecified,
                    # write the IP string to the output file.
                    if not ip.is_link_local and not ip.is_multicast and not ip.is_unspecified:
                        ipv6_writer.writerow([ip_str])

            # If the IP string was not a valid IP address, catch the ValueError and do nothing.
            except ValueError:
                pass