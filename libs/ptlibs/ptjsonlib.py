import json
import sys
import uuid

from libs.ptlibs.ptprinthelper import out_if, out_ifnot, ptprint
from libs.ptlibs.pathtypedetector import PathTypeDetector


class PtJsonLib:
    def __init__(self, guid="", status="") -> None:
        self.json_object = {
            "guid": guid,
            "status": status,
            "message": "",
            "result": {
                "nodes": [],
                "properties": [],
                "vulnerabilities": []
            }
        }

    def set_guid(self, guid: str) -> None:
        self.json_object["guid"] = guid

    def add_node(self, node_object: dict) -> None:
        """Adds node to json_object"""
        assert type(node_object) is dict
        self.json_object["result"]["nodes"].append(node_object)

    def add_nodes(self, nodes: list) -> None:
        """Adds nodes to json_object"""
        assert type(nodes) is list
        for node in nodes:
            self.add_node(node)

    def parse_url2nodes(self, url: str) -> list[dict]:
        """Parses url to node object"""
        base_url = self.get_base_url(url)
        nodes = []
        parent = None
        paths = self.get_paths(url)
        for i, path in enumerate(paths):
            name = path
            url = f"{base_url}/{'/'.join(paths[0:i+1])}"
            page_type = PathTypeDetector(path).get_type()
            parent_type = "rootDirectory" if i == 0 else None
            properties = {"name": name, "url": url, "WebPageType": page_type}
            node_object = self.create_node_object("webPage", parent_type, parent, properties)
            if type(node_object) is not str: #check whether node already exists
                parent = node_object["ident"]
                nodes.append(node_object)
            else:
                parent = node_object
        return nodes

    def get_base_url(self, url: str) -> str:
        """Returns base url"""
        schema_separator = "://"
        schema_split = url.split(schema_separator)
        schema = schema_split[0] if len(schema_split) > 1 else ""
        address = schema_split[-1]
        base_address = address.split("/")[0]
        return f"{schema + schema_separator if schema else ''}{base_address}"

    def get_paths(self, url: str) -> list[str]:
        """Returns paths from url"""
        return url.strip("/").split("/")[1:]

    def create_node_object(self, node_type: str, parent_type=None, parent=None, properties : dict = {}) -> dict:
        """Creates node object"""
        assert type(properties) is dict
        ident = self.node_duplicity_check(parent_type, properties)
        if ident:
            return ident
        return {"type": node_type, "parent_type": parent_type, "ident": self.create_guid(), "parent": parent, "properties": properties}

    def node_duplicity_check(self, parent_type, properties: dict) -> str | None:
        """Returns node ident if node already exists in json_object else returns None"""
        if not parent_type:
            return None
        for node in self.json_object["result"]["nodes"]:
            if node["parent_type"] == parent_type:
                if node["properties"] == properties:
                    return node["ident"]
        return None

    def create_guid(self) -> str:
        """Creates random guid"""
        return str(uuid.uuid4())

    def property_duplicity_check(self, name: str, value: str) -> bool:
        """Check if a property with the same name and value already exists"""
        for prop in self.json_object["result"]["properties"]:
            if prop.get("name") == name and prop.get("value") == value:
                return True
        return False

    def add_property(self, name: str, value: str) -> None:
        if self.property_duplicity_check(name, value):
            return
        
        self.json_object["result"]["properties"].append({"name": name, "value": value})

    def vulnerability_duplicity_check(self, code: str, description: str) -> bool:
        """Check if a vulnerability with the same code and description already exists"""
        for vuln in self.json_object["result"]["vulnerabilities"]:
            if vuln.get("code") == code and vuln.get("description") == description:
                return True
        return False

    def add_vulnerability(self, code: str, request: str=None, response: str=None, description: str=None, score: str=None, note: str=None) -> None:
        if self.vulnerability_duplicity_check(code, description):
            return
        
        vuln_dict = {k:v for k, v in locals().items() if v is not None}
        vuln_dict.pop("self", None)
        self.json_object["result"]["vulnerabilities"].append(vuln_dict)

    def set_status(self, status: str, message: str = "") -> None:
        self.json_object["status"] = status
        if message:
            self.json_object["message"] = message

    def get_result_json(self) -> str:
        return json.dumps(self.json_object, indent=4)

    def end_error(self, message, condition):
        ptprint( out_ifnot(f"Error: {message}", "ERROR", condition) )
        self.set_status("error", message)
        ptprint( out_if(self.get_result_json(), None, condition) )
        sys.exit(1)

