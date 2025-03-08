import csv
import os
import pandas as pd
from scapy.all import *
from libs.check import has_additional_data
import numpy as np

# Get the directory of the currently running Python script
current_directory = os.path.dirname(os.path.realpath(__file__))

def create_csv(directory):
    # Create the initial CSV files
    with open(f"{directory}/packets.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/routers.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/mDNS.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/LLMNR.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/MLDv1.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/MLDv2.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'rtype', 'mulip', 'sources']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/RA.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft', 'Reachable_time', 'Retrans_time',
                    'DNS', 'MTU', 'Prefix', 'Valid_lft', 'Preferred_lft']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    # For storing local name when asking with mDNS and LLMNR
    with open(f"{directory}/localname.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'name']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    # For storing the role of every device (host, router, preferred router)
    with open(f"{directory}/role_node.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'Device_Number', 'Role']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    with open(f"{directory}/ipv6_route_table.csv", 'w', newline='') as csvfile:
        fieldnames = ['Destination', 'Nexthop', 'Flag', 'Metric', 'Refcnt', 'Use', 'If']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    with open(f"{directory}/ipv4_route_table.csv", 'w', newline='') as csvfile:
        fieldnames = ['Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/time_all.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/time_incoming.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/time_outgoing.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/start_end_mode.csv", 'w', newline='') as csvfile:
        fieldnames = ['time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/eap.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/remote_node.csv", 'w', newline='') as csvfile:
        fieldnames = ['src MAC', 'dst MAC', 'src IP', 'dst IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/dhcp.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
    # with open(f"{directory}/ipv6.csv", 'w', newline='') as csvfile:
    #     fieldnames = ['IP']
    #     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    #     writer.writeheader()


def sort_csv_based_MAC(interface, file_name):
    '''
    Sorting csv files with ascending order based on MAC, if they have. It also remove entry from your sender
    and save them back to the file
    '''
    if has_additional_data(file_name):
        # Read the CSV file into a DataFrame
        df = pd.read_csv(file_name)

        # Specify the MAC address you want to remove
        specified_mac = get_if_hwaddr(interface)

        # Remove entries with the specified MAC address
        df_filtered = df[df['MAC'] != specified_mac]

        # Sort the remaining DataFrame based on the MAC column in ascending order
        df_sorted = df_filtered.sort_values(by='MAC')

        # If there is a column named 'IP', sort the IPs associated with each MAC
        if 'IP' in df_sorted.columns:
            df_sorted['IP'] = df_sorted.groupby('MAC')['IP'].transform(lambda x: x.sort_values().values)

        # Save the sorted DataFrame back to a CSV file
        df_sorted.to_csv(file_name, index=False)


def sort_csv_role_node(interface, file_name):
    '''
    Finding the order number of every device with its role (host, router, preferred router) from csv file
    and store it into the csv file called role_node.csv
    '''
    if has_additional_data("src/tmp/addresses.csv"):
        # Sorting files based on MAC
        sort_csv_based_MAC(interface, "src/tmp/addresses.csv")
        sort_csv_based_MAC(interface, "src/tmp/RA.csv")


        # Finding the number of devices
        df1 = pd.read_csv('src/tmp/addresses.csv')

        # Dictionary to store device MAC addresses and their corresponding numbers
        device_numbers = {}

        # Iterate through each row in the DataFrame
        for index, row in df1.iterrows():
            mac_address = row['MAC']
            # If the MAC address is not already in the dictionary, add it with a new number
            if mac_address not in device_numbers:
                device_numbers[mac_address] = len(device_numbers) + 1

        # Create a DataFrame to store MAC addresses and their corresponding device numbers
        new_df = pd.DataFrame({'MAC': list(device_numbers.keys()), 'Device_Number': list(device_numbers.values())})

        # Write the new DataFrame to a new CSV file
        new_df.to_csv(file_name, index=False)

        # Finding the role of each node
        df2 = pd.read_csv('src/tmp/RA.csv')

        # Dictionary to store device roles based on MAC addresses
        device_roles = {}

        # Iterate through each row in the DataFrame
        for index, row in df2.iterrows():
            mac_address = row['MAC']
            preference = row['Preference']
            router_lft = row['Router_lft']
            valid_lft = row['Valid_lft']
            
            # Determine the role based on the given criteria
            if preference == "High" and int(router_lft) > 0:
                device_roles[mac_address] = "Preferred router"
            elif preference == "Medium" and int(router_lft) > 0:
                # Check if there are no devices with higher preference than Medium
                higher_preference_devices = df2[(df2['MAC'] != mac_address) & (df2['Preference'].isin(['High', 'Reserved']))]
                if higher_preference_devices.empty:
                    device_roles[mac_address] = "Preferred router"
                else:
                    device_roles[mac_address] = "Router"
            elif preference == "Low" and int(router_lft) > 0:
                # Check if there are no devices with higher preference than Low
                higher_preference_devices = df2[(df2['MAC'] != mac_address) & (df2['Preference'].isin(['High', 'Medium', 'Reserved']))]
                if higher_preference_devices.empty:
                    device_roles[mac_address] = "Preferred router"
                else:
                    device_roles[mac_address] = "Router"
            else:
                device_roles[mac_address] = "Router"

        # Create a new DataFrame to store MAC addresses, Device Numbers, and Roles
        new_df = pd.DataFrame({'MAC': list(device_roles.keys()), 'Role': list(device_roles.values())})

        # Read the existing DataFrame containing MAC addresses and Device Numbers
        if has_additional_data(file_name):
            existing_df = pd.read_csv(file_name)

            # Merge the existing DataFrame with the new DataFrame based on MAC addresses
            final_df = pd.merge(existing_df, new_df, on='MAC', how='left')

            # Write the final DataFrame to a new CSV file
            final_df.to_csv(file_name, index=False)

            # Fill in the blank data with Host
            final_df = pd.read_csv(file_name)

            blank_role_rows = final_df[final_df['Role'].isna() | (final_df['Role'] == '')]

            # Fill blank 'Role' column with "Host"
            host_str = 'Host'  # Use a plain string instead of np.compat.asbytes
            final_df.loc[blank_role_rows.index, 'Role'] = host_str

            # Write the updated DataFrame to the CSV file
            final_df.to_csv(file_name, index=False)

def delete_middle_content_csv(filename): 
    """
  Checks if the CSV file has at least 3 rows and modifies it if needed.
  Args:
      filename (str): Path to the CSV file.
  Returns:
      None
    """
    try:
        # Read the CSV file into a pandas DataFrame
        df = pd.read_csv(filename)
        # Check if there are at least 3 rows excluding the header
        if len(df) > 3:
            # Select the desired rows
            df = df[df.index.isin([0, -1]) | ~df.index.isin(range(1, len(df) - 1))]

            # Save the modified DataFrame to a new CSV file
            df.to_csv(filename, index=False)
        else:
            pass

    except FileNotFoundError:
        pass
        




    


    

