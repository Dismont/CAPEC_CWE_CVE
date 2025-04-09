import entity
from typing import Any

from entity import PersonalComputer, Switch


def main():
    network_elements = []
    network_elements.append(entity.PersonalComputer("PC1"))
    network_elements.append(entity.PersonalComputer("PC2"))
    network_elements.append(entity.Switch("SW1"))
    network_elements.append(entity.Switch("SW2"))

    network_elements[0].network_layer.update({"RJ-45": network_elements[2]})
    network_elements[1].network_layer.update({"RJ-45": network_elements[2]})

    network_elements[2].network_layer.update({"Ethernet 1": network_elements[0]})
    network_elements[2].network_layer.update({"Ethernet 2": network_elements[1]})
    network_elements[2].network_layer.update({"Ethernet 3": network_elements[3]})
    network_elements[3].network_layer.update({"Ethernet 1": network_elements[2]})


    for i in range(len(network_elements)):
        print(f" --- --- {i+1} --- ---")
        print(network_elements[i].print_all_data())
        print(f"List of next nodes: {network_elements[i].get_next_node()}")
        print("-"*100)

    recursion_node_walker(checklist=[network_elements[0].configuration["Hostname"]],root_node=network_elements[0])

def recursion_node_walker(checklist:list[str],root_node:PersonalComputer | Switch):
    next_nodes = root_node.get_next_node()
    print("The predict of next nodes:")
    for node in next_nodes:
        print(f"--> {node}")
    if len(next_nodes) == 1:
        next_nodes = root_node.get_next_node()[0]
        if next_nodes.configuration["Hostname"] not in checklist:
            checklist.append(next_nodes.configuration["Hostname"])
            print(f"{root_node.configuration["Hostname"]} --> {next_nodes.configuration["Hostname"]} <=> {checklist} | + |")
            return recursion_node_walker(checklist=checklist,root_node=next_nodes)
        else:
            print(f"{root_node.configuration["Hostname"]} --> {next_nodes.configuration["Hostname"]} <=> {checklist} | - |")

    else:
        for node in next_nodes:
            if not node:
                continue
            else:
                if node.configuration["Hostname"] not in checklist:
                    checklist.append(node.configuration["Hostname"])
                    print(f"{root_node.configuration["Hostname"]} --> {node.configuration["Hostname"]} <=> {checklist} | + |")
                    return recursion_node_walker(checklist=checklist,root_node=node)
                else:
                    print(f"{root_node.configuration["Hostname"]} --> {node.configuration["Hostname"]} <=> {checklist} | - |")
                    continue





if __name__ == "__main__":
    main()