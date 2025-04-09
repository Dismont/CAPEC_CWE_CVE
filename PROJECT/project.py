from PROJECT import entity

from PROJECT.entity import PersonalComputer, Switch


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
        print(f"List of next nodes: {network_elements[i].get_next_node}")
        print("-"*100)

    for element in network_elements:
        print(recursion_node_walker(checklist=[f"{element.configuration["Hostname"]},"],root_node=element))


def recursion_node_walker(checklist:list[str],root_node:PersonalComputer | Switch) -> list[str]:

    next_nodes = root_node.get_next_node

    if len(next_nodes) == 1:
        for i in range(len(checklist)):
            checklist[i] += f"{next_nodes[0].get_hostname},"
            print(*checklist, sep=" ")
        return recursion_node_walker(checklist=checklist, root_node=next_nodes[0])

    else:
        for node in next_nodes:

            if not node:
                continue

            else:
                new_checklist = []
                for i in range(len(checklist)):
                    review = checklist[i].split(",")
                    if node.get_hostname not in review:
                        new_line = f"{checklist[i] + node.get_hostname},"
                        new_checklist.append(new_line)
                checklist = new_checklist
                print(*checklist, sep=" ")
                return recursion_node_walker(checklist=checklist, root_node=node)


    return checklist












if __name__ == "__main__":
    main()