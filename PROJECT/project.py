from entity import PersonalComputer, Switch, Router


def main():
    network_elements = [
        PersonalComputer("PC1"),  # 0
        PersonalComputer("PC2"),  # 1
        Switch("SW1"),  # 2
        Switch("SW2"),  # 3
        Router("RT1"),  # 4
        Router("RT2"),  # 5
        Switch("SW3"),  # 6
    ]

    # PC1 <--> SW1 (0-2 2-0)
    network_elements[0].network_layer.update({"RJ-45": network_elements[2]})
    network_elements[2].network_layer.update({"Ethernet 1": network_elements[0]})
    # SW1 <--> RT1 (2-4 4-2)
    network_elements[2].network_layer.update({"Ethernet 2": network_elements[4]})
    network_elements[4].network_layer.update({"Ethernet 1": network_elements[2]})
    # RT1 <--> RT2 (4-5 5-4)
    network_elements[4].network_layer.update({"Ethernet 2": network_elements[5]})
    network_elements[5].network_layer.update({"Ethernet 1": network_elements[4]})
    # RT2 <--> SW2 (5-3 3-5)
    network_elements[5].network_layer.update({"Ethernet 2": network_elements[3]})
    network_elements[3].network_layer.update({"Ethernet 1": network_elements[5]})
    # SW2 <--> PC2 (3-1 1-3)
    network_elements[3].network_layer.update({"Ethernet 2": network_elements[1]})
    network_elements[1].network_layer.update({"RJ-45": network_elements[3]})
    # SW3 <--> RT2 (6-5 5-6)
    network_elements[6].network_layer.update({"Ethernet 1": network_elements[5]})
    network_elements[5].network_layer.update({"Ethernet 2": network_elements[6]})
    # SW3 <--> SW2 (6-3 3-6)
    network_elements[6].network_layer.update({"Ethernet 2": network_elements[3]})
    network_elements[3].network_layer.update({"Ethernet 3": network_elements[6]})

    paths = recursion_find_path(start_node=network_elements[0], end_node=network_elements[1])
    print(tuple(path.hostname for path in paths))


def recursion_find_path(start_node: PersonalComputer | Switch | Router, end_node: PersonalComputer | Switch | Router,
                        path: list[str] = None):
    if not hasattr(start_node, "next_nodes") or not start_node.next_nodes:
        return []

    if start_node == end_node:
        return path

    if path is None:
        path = []

    path = path + [start_node]

    paths = []
    for node in start_node.next_nodes:
        if node not in path:
            new_paths = recursion_find_path(node, end_node, path)
            for new_path in new_paths:
                paths.append(new_path)
    return paths


if __name__ == "__main__":
    main()
