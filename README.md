```
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|      ptnetinspector v0.1.7
                                       https://www.penterep.com
```

<span style="color:orange;">ptnetinspector</span> is a versatile tool designed to 
perform comprehensive scans over IPv6 networks, with support for dual-stack environments 
to ensure compatibility with both IPv4 and IPv6 infrastructures. This tool provides detailed 
insights into the network's topology, identifying critical information such as IP, MAC, 
multicast groups, router information and the role of discovered nodes.

Beyond basic network reconnaissance, this Penterep tool is equipped with advanced vulnerability 
detection capabilities, scanning nodes for known security weaknesses and misconfigurations. 
This enables network administrators to proactively identify and mitigate risks.


## Install Requirements  
 
Before proceeding, it is recommended to update your system to ensure compatibility:  
```bash  
sudo apt update && sudo apt upgrade -y  
```  

This application requires **Python3**. Make sure it is installed, along with the `python3-venv` package, for managing virtual environments:  
```bash  
sudo apt install python3 python3-venv -y  
```  

### Installation Methods

You can install ptnetinspector in two ways:

#### Method 1: Install from PyPI (Recommended for Users)

The easiest way to install ptnetinspector is directly from PyPI:

```bash
# Create and activate a virtual environment (recommended)
python3 -m venv myenv
source myenv/bin/activate

# Install from PyPI
pip install ptnetinspector
```

#### Method 2: Install from Source (For Development)

If you want to modify the code or contribute to development:

##### 1. **Create a Virtual Environment (if not already created)**  
You can create a virtual environment with any name you prefer. Replace `<env_name>` with your chosen name in the following command:  
```bash
python3 -m venv <env_name>
```
For example, if you want to name your virtual environment `myenv`, use:  
```bash
python3 -m venv myenv
```

##### 2. **Activate the Virtual Environment**  
After creating the virtual environment, activate it by specifying its name. Replace `<env_name>` with the name you used during creation:  
```bash
source <env_name>/bin/activate
```
For instance, if the name is `myenv`, use:  
```bash
source myenv/bin/activate
```

##### 3. **Install the package**

After cloning the repository, install the package in editable/development mode:

```bash
# inside your activated virtual environment
pip install -e .
# or for a regular install:
pip install .
```

Installing with `-e` (editable) lets you edit the source in-place and run the installed command without reinstalling.

### Important Notes  
For future use, you don’t need to reinstall the dependencies. Simply activate the created virtual environment before running the application:  
```bash  
source myenv/bin/activate 
```  
By following these steps, you ensure a clean and consistent installation process while avoiding potential errors due to system-level dependency conflicts or pip management.  


## Usage
This tool has 4 primary modes (802.1x, passive, active, aggressive). Some of these modes can be combined to perform a more complex task. The tool must be run under the <span style="color:red;">**root**</span> user in Linux (```sudo```). The meaning of every mode and parameters are explained below.

```
ptnetinspector -t 802.1x/a/a+/p -i eth0 -j -less
```

### General Options

The following options are applicable to all scan modes:

| Option  | Description |
|---------|-------------|
| `-t`    | Type of scan (**mandatory**, can choose more than one): <br> - `802.1x`: Network test for 802.1x protocol <br> - `a`: Active mode for network scanning <br> - `a+`: Aggressive mode for network scanning <br> - `p`: Passive mode for network scanning |
| `-i`    | Interface (**mandatory**) |
| `-target` | Target device(s) by MAC address (space-separated or repeated). Filters output to only show results for specified MAC(s). Example: `-target ca:01:08:2b:00:01 -target 00:0c:29:35:45:d8` or `-target ca:01:08:2b:00:01 00:0c:29:35:45:d8` |
| `-j`    | Output in JSON format. Displays only JSON output unless used with other options. Includes errors if present. |
| `-vv` | Displays full details of the network scan. When used with `-j`, outputs detailed and JSON data. Default: Basic details are shown. |
| `-less` | Displays minimum details of the network scan. When used with `-j`, outputs minimal and JSON data. Default: Basic details are shown. |
| `-nc`   | Disables checking if found addresses are valid and responsive. |
| `-4`    | Only scan IPv4 traffic (cannot be used alone for `a+` mode). |
| `-6`    | Only scan IPv6 traffic. |
| `-ts`   | Filter vulnerabilities by Test code (space-separated). Only selected tests will be scanned and reported. The tool will **automatically infer and schedule the required scan mode(s)**. Example: `-ts 4-MDNS 4-LLMNR 6-OUTRANGE` will auto-infer mode `a` (active). Mixed modes like `-ts 6-OUTRANGE 802-1X` will infer `[802.1x, a]`. |
| `-tmpret` | Temporary file retention in seconds (default: 1800). Set a small value for quick cleanup during development. |
| `-h`    | Displays help message and exits. |

### Specific Options for Passive Scanning

| Option  | Description |
|---------|-------------|
| `-d`    | Duration of the passive scan in seconds (floating-point allowed). Default: 30 seconds. |

### Specific Options for Active Scanning

| Option  | Description |
|---------|-------------|
| `-smac` | Scanner's MAC address. Default: Taken from the interface specified by `-i`. |

### Specific Options for Aggressive Scanning

| Option     | Description |
|------------|-------------|
| `-da+`     | Duration of the aggressive scan in seconds (floating-point allowed). Default: 30 seconds. |
| `-prefix`  | Prefix advertised by the scanner. Default: `fe80::/64`. |
| `-smac`    | Scanner's MAC address. Default: Taken from the interface specified by `-i`. |
| `-sip`     | Scanner's IPv6 address. Default: Taken from the interface specified by `-i`. Prefers a link-local address. |
| `-rpref`   | Router preference flag (`Reserved`, `Low`, `Medium`, `High`). Default: `High`. |
| `-period`  | Rate of RA packet sending (1 packet per `-period` seconds, floating-point allowed). Default: `Aggressive duration / 10`. |
| `-chl`     | Current hop limit in RA messages. Default: 0. |
| `-mtu`     | MTU advertised on the link. Excluded if not specified. |
| `-dns`     | IPv6 address(es) of DNS server(s). Multiple addresses can be space-separated. Excluded if not specified. Required for FAKERADNS vulnerability testing (part of FAKERA tests). |
| `-nofwd`   | Prevents the scanner from forwarding packets (MiTM). Forwarding is allowed by default. |

## Examples

### 802.1x Mode
Send an EAPOL-Start and wait for responses.
```
ptnetinspector -t 802.1x -i eth0 -j
```

### Passive Mode
Deactivate outgoing traffic, disable IP, and sniff incoming packets.
```
ptnetinspector -t p -i eth0 -less
```

### Active Mode
Test vulnerabilities with packets such as MLD, ICMPv6, LLMNR, and mDNS.
```
ptnetinspector -t a -i eth0 -vv
```

### Aggressive Mode
Perform active scans while emulating a fake router. Configure additional parameters.
```
ptnetinspector -t a+ -i eth0 -j -da+ 35 -prefix 2001:1::/64 -smac 00:01:02:03:04:05 -sip fe80::1 -period 5
```

### Combination of Modes
Combine 802.1x and passive scans for a complex scenario. Specify passive scan duration.
```
ptnetinspector -t 802.1x p -i eth0 -j -d 10
```

### Target-Specific Vulnerability Scanning
Filter and scan only specific vulnerabilities using their Test codes. The tool will **automatically infer the appropriate scan mode(s)** and IP version(s) based on the test codes provided.

Scan IPv4 multicast tests:
```
ptnetinspector -ts 4-MDNS 4-LLMNR -i eth0 -j
```

Test ICMPv6 OUTRANGE vulnerability (auto-infers active mode):
```
ptnetinspector -ts 6-OUTRANGE -i eth0
```

Test FAKERA vulnerabilities (requires DNS to be specified for FAKERADNS detection):
```
ptnetinspector -ts 6-FAKERA -i eth0 -dns 2001:4860:4860::8888
```

Combine multiple test codes (auto-infers mode `a`):
```
ptnetinspector -ts 6-MLDV1 6-OUTRANGE -i eth0 -j
```

Mixed 802.1x and other tests (auto-infers modes `[802.1x, a]`):
```
ptnetinspector -ts 802-1X 6-OUTRANGE 4-MULTIECHO -i eth0
```

### Target-Specific Device Filtering
Filter scan results to focus on specific devices using their MAC addresses:

Scan and display results for a single target device:
```
ptnetinspector -t a -i eth0 -target ca:01:08:2b:00:01
```

Scan and display results for multiple target devices (using repeated flag):
```
ptnetinspector -t a -i eth0 -target ca:01:08:2b:00:01 -target 00:0c:29:35:45:d8
```

Scan and display results for multiple target devices (using space-separated):
```
ptnetinspector -t a -i eth0 -target ca:01:08:2b:00:01 00:0c:29:35:45:d8
```

## License
Copyright (c) 2025 Penterep Security s.r.o.

ptnetinspector is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptnetinspector is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptmethods. If not, see https://www.gnu.org/licenses/

## Sponsor

<p align="center">
  <a href="https://www.penterep.com/">
    <img alt="Penterep" width="300" src="https://cms.penterep.com/uploads/horizontal_penterep_logo_normal_3562db3de4.svg" />
  </a>
</p>


## Disclaimer

```
This program must be performed with proper authorization or Educational purpose ONLY. Do not use it without permission. 
The usual disclaimer applies, especially the fact that us (Penterep) is not liable for any damages caused by direct or 
indirect use of the functionality provided by this program. The author bears NO responsibility for content or misuse of 
this program or any derivatives thereof. 
```
