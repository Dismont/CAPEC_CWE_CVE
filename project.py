import entity
from typing import Any

def main():
    network_elements = []
    network_elements.append(entity.PersonalComputer("PC1"))
    network_elements.append(entity.PersonalComputer("PC2"))
    network_elements.append(entity.Switch("SW1"))

    network_elements[0].network_layer.update({"RJ-45": network_elements[2]})
    network_elements[1].network_layer.update({"RJ-45": network_elements[2]})

    network_elements[2].network_layer.update({"Ethernet 1": network_elements[0]})
    network_elements[2].network_layer.update({"Ethernet 2": network_elements[1]})

    for element in network_elements:
        print(element.print_all_data())
        print(element.get_next_node())
        print("#"*100)


def recursion_node_walker():
    pass




if __name__ == "__main__":
    main()