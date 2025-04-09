
class PersonalComputer:

    def __init__(self,hostname=""):

        self.configuration = {
            "Hostname" : hostname,
            "Type"     : "PC"
        }

        self.network_layer = {
            "RJ-45":""
        }
        self.hardware_layer = {
            "MotherBoard" : "",
            "CPU" : "",
            "RAM" : "",
            "GPU" : "",
            "Storage" : "",
            "Power unit" : ""
        }
        self.system_layer = {
            "OS" : "",
            "OS version" : ""
        }

        self.application_layer = {
            "App": "",
            "App version": ""
        }

        self.user_layer = {
            "Mouse" : "",
            "Keyboard" : "",
            "Display" : ""
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
        print("Configuration\n\t\t\t\t",end=""), print(*self.configuration.items(),sep="\n\t\t\t\t")
        print("Network Layer\n\t\t\t\t",end=""), print(*self.network_layer.items(),sep="\n\t\t\t\t")
        print("Hardware Layer\n\t\t\t\t",end=""), print(*self.hardware_layer.items(),sep="\n\t\t\t\t")
        print("System Layer\n\t\t\t\t",end=""), print(*self.system_layer.items(),sep="\n\t\t\t\t")
        print("Application Layer\n\t\t\t\t",end=""), print(*self.application_layer.items(),sep="\n\t\t\t\t")
        print("User Layer\n\t\t\t\t",end=""), print(*self.user_layer.items(),sep="\n\t\t\t\t")

    @property
    def next_nodes(self):
        return  list(self.network_layer.values())



class Switch:

    def __init__(self,hostname=""):
        self.configuration = {
            "Hostname": hostname,
            "Type": "Switch"
        }

        self.network_layer = {
            "Ethernet 1" : "",
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

        for key,value in self.network_layer.items():
            if value == "": continue
            else: query.append(value)

        return  query
