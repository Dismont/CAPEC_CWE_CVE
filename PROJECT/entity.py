class PersonalComputer:

    def __init__(self, hostname=""):
        self.configuration = {
            "Hostname": hostname,
            "Type": "PC"
        }

        self.network_layer = {
            "RJ-45": ""
        }
        self.hardware_layer = {
            "MotherBoard": "",
            "CPU": "",
            "RAM": "",
            "GPU": "",
            "Storage": "",
            "Power unit": ""
        }
        self.system_layer = {
            "OS": "",
            "OS version": ""
        }

        self.application_layer = {
            "App": "",
            "App version": ""
        }

        self.user_layer = {
            "Mouse": "",
            "Keyboard": "",
            "Display": ""
        }

    @property
    def hostname(self):
        return self.configuration["Hostname"]

    def get_network_cve(self):
        pass

    def get_hardware_cve(self):
        pass

    def get_system_cve(self):
        pass

    def get_app_cve(self):
        pass

    def get_user_cve(self):
        pass

    def print_all_data(self):
        print("Configuration\n\t\t\t\t", end=""), print(*self.configuration.items(), sep="\n\t\t\t\t")
        print("Network Layer\n\t\t\t\t", end=""), print(*self.network_layer.items(), sep="\n\t\t\t\t")
        print("Hardware Layer\n\t\t\t\t", end=""), print(*self.hardware_layer.items(), sep="\n\t\t\t\t")
        print("System Layer\n\t\t\t\t", end=""), print(*self.system_layer.items(), sep="\n\t\t\t\t")
        print("Application Layer\n\t\t\t\t", end=""), print(*self.application_layer.items(), sep="\n\t\t\t\t")
        print("User Layer\n\t\t\t\t", end=""), print(*self.user_layer.items(), sep="\n\t\t\t\t")

    @property
    def next_nodes(self):
        return list(self.network_layer.values())


class Switch:

    def __init__(self, hostname=""):
        self.configuration = {
            "Hostname": hostname,
            "Type": "Switch"
        }

        self.network_layer = {
            "Ethernet 1": "",
            "Ethernet 2": "",
            "Ethernet 3": "",
            "Ethernet 4": "",
            "Ethernet 5": "",
            "Ethernet 6": "",
            "Ethernet 7": "",
            "Ethernet 8": "",
            "Ethernet 9": "",
            "Ethernet 10": "",
            "Ethernet 11": "",
            "Ethernet 12": "",
            "Ethernet 13": "",
            "Ethernet 14": "",
            "Ethernet 15": "",
            "Ethernet 16": "",
            "Ethernet 17": "",
            "Ethernet 18": "",
            "Ethernet 19": "",
            "Ethernet 20": "",
            "Ethernet 21": "",
            "Ethernet 22": "",
            "Ethernet 23": "",
            "Ethernet 24": "",
        }
        self.hardware_layer = {
            "MotherBoard": "",
            "CPU": "",
            "RAM": "",
            "Storage": "",
            "Power unit": ""
        }
        self.system_layer = {
            "OS": "",
            "OS version": ""
        }

    def print_all_data(self):
        print("Configuration\n\t\t\t\t", end=""), print(*self.configuration.items(), sep="\n\t\t\t\t")
        print("Network Layer\n\t\t\t\t", end=""), print(*self.network_layer.items(), sep="\n\t\t\t\t")
        print("Hardware Layer\n\t\t\t\t", end=""), print(*self.hardware_layer.items(), sep="\n\t\t\t\t")
        print("System Layer\n\t\t\t\t", end=""), print(*self.system_layer.items(), sep="\n\t\t\t\t")

    @property
    def hostname(self):
        return self.configuration["Hostname"]

    @property
    def next_nodes(self):

        query = []

        for key, value in self.network_layer.items():
            if value == "":
                continue
            else:
                query.append(value)

        return query


class Router:
    def __init__(self, hostname=""):
        self.configuration = {
            "Hostname": hostname,
            "Type": "Switch"
        }

        self.network_layer = {
            "Ethernet 1": "",
            "Ethernet 2": "",
            "Ethernet 3": "",
            "Ethernet 4": "",

        }
        self.hardware_layer = {
            "MotherBoard": "",
            "CPU": "",
            "RAM": "",
            "Storage": "",
            "Power unit": ""
        }
        self.system_layer = {
            "OS": "",
            "OS version": ""
        }

    def print_all_data(self):
        print("Configuration\n\t\t\t\t", end=""), print(*self.configuration.items(), sep="\n\t\t\t\t")
        print("Network Layer\n\t\t\t\t", end=""), print(*self.network_layer.items(), sep="\n\t\t\t\t")
        print("Hardware Layer\n\t\t\t\t", end=""), print(*self.hardware_layer.items(), sep="\n\t\t\t\t")
        print("System Layer\n\t\t\t\t", end=""), print(*self.system_layer.items(), sep="\n\t\t\t\t")

    @property
    def hostname(self):
        return self.configuration["Hostname"]

    @property
    def next_nodes(self):

        query = []

        for key, value in self.network_layer.items():
            if value == "":
                continue
            else:
                query.append(value)

        return query


class Database:

    def __init__(self):
        # --- CREATE query ---
        self.create_capec \
            = """create table IF NOT EXISTS `CAPEC` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                capec_id INTEGER NOT NULL UNIQUE,
                capec_name VARCHAR(150) NOT NULL UNIQUE,
                capec_description TEXT NOT NULL,
                capec_type VARCHAR(50) NOT NULL);"""
        self.create_cwe \
            = """create table IF NOT EXISTS `CWE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                cwe_id INTEGER NOT NULL UNIQUE,
                cwe_name VARCHAR(150) NOT NULL UNIQUE,
                cwe_description TEXT NOT NULL,
                cwe_type VARCHAR(50) NOT NULL);"""
        self.create_cve \
            = """create table IF NOT EXISTS `CVE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                cve_id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, 
                cve_name VARCHAR(150) NOT NULL UNIQUE,
                cve_description TEXT NOT NULL,
                cve_link VARCHAR(150) NOT NULL UNIQUE,
                cve_cvss_v2_vector VARCHAR(150) NOT NULL,
                cve_cvss_v2_basescore INTEGER NOT NULL,
                cve_cvss_v3_vector VARCHAR(150) NOT NULL,
                cve_cvss_v3_basescore INTEGER NOT NULL );"""
        self.create_cpe \
            = """create table IF NOT EXISTS `CPE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                cve_id INTEGER NOT NULL UNIQUE, 
                cpe_string VARCHAR(60) NOT NULL UNIQUE,
                cpe_status VARCHAR(30) NOT NULL, 
                cpe_link VARCHAR(60) NOT NULL UNIQUE, 
                cpe_part VARCHAR(40) NOT NULL, 
                cpe_vendor VARCHAR(40) NOT NULL, 
                cpe_product VARCHAR(40) NOT NULL, 
                cpe_version VARCHAR(20) NOT NULL, 
                cpe_update VARCHAR(30) NOT NULL, 
                cpe_edition VARCHAR(30) NOT NULL, 
                cpe_language VARCHAR(30) NOT NULL, 
                cpe_edition_sw VARCHAR(30) NOT NULL, 
                cpe_target_sw VARCHAR(30) NOT NULL, 
                cpe_target_hw VARCHAR(30) NOT NULL, 
                cpe_other VARCHAR(30) NOT NULL);"""

        # --- CREATE *CROSS-TABLE* query ---
        self.create_capec_to_cwe \
            = """create table IF NOT EXISTS `CAPEC_to_CWE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                capec_id INTEGER NOT NULL,
                cwe_id INTEGER NOT NULL);"""
        self.create_capec_parentof \
            = """create table IF NOT EXISTS `CAPEC_parentof` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                capec_parent INTEGER NOT NULL,
                capec_child  INTEGER NOT NULL);"""
        self.create_cwe_to_cve \
            = """create table IF NOT EXISTS `CWE_to_CVE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                cwe_id INTEGER NOT NULL,
                cve_id INTEGER NOT NULL);"""
        self.create_cwe_parentof \
            = """create table IF NOT EXISTS `CWE_parentof` (
                id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
                cwe_parent INTEGER NOT NULL,
                cwe_child  INTEGER NOT NULL);"""

        # --- INSERT query ---
        self.insert_capec \
            = "insert into `CAPEC` (capec_id, capec_name, capec_description, capec_type) values"
        self.insert_cwe \
            = "insert into `CWE` (cwe_id, cwe_name, cwe_description, cwe_type) values"
        self.insert_cve \
            = "insert into `CVE` (cve_id, cve_name, cve_description, cve_link, cve_cvss_v2_vector, cve_cvss_v2_basescore, cve_cvss_v3_vector, cve_cvss_v3_basescore) values"
        self.insert_cpe \
            = "insert into `CPE` (cve_id, cpe_string, cpe_status, cpe_link, cpe_part, cpe_vendor, cpe_product, cpe_version, cpe_update, cpe_edition, cpe_language, cpe_edition_sw, cpe_target_sw, cpe_target_hw, cpe_other) values"

        # --- INSERT *CROSS-TABLE* query ---
        self.insert_capec_parentof \
            = "insert into `CAPEC_parentof` (capec_parent, capec_child) values"
        self.insert_capec_to_cwe \
            = "insert into `CAPEC_to_CWE` (capec_id, cwe_id) values"
        self.insert_cwe_parentof \
            = "insert into `CWE_parentof` (cwe_parent, cwe_child) values"
        self.insert_cwe_to_cve \
            = "insert into `CWE_to_CVE` (cwe_id, cve_id) values"