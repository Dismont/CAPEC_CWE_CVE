import json
class PersonalComputer:

    def __init__(self):

        self.configuration = {
            "Hostname" : ""
        }

        self.network_layer = {
                "Type" : "PC"
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
        print(f"""
        Configuration       : {self.configuration},
        Network Layer       : {self.network_layer},
        Hardware Layer      : {self.hardware_layer},
        System Layer        : {self.system_layer},
        Application Layer   : {self.application_layer},
        User Layer          : {self.user_layer}
        """)

class Switch:

    def __init__(self):
        self.configuration = {
            "Hostname": ""
        }

        self.network_layer = {
            "Type": "Switch",
            "" : ""
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

