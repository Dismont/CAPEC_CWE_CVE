from PROJECT.entity import PersonalComputer, Switch


def main():

    network_elements = []
    # 0
    network_elements.append(PersonalComputer("PC1"))
    # 1
    network_elements.append(PersonalComputer("PC2"))
    # 2
    network_elements.append(Switch("SW1"))
    # 3
    network_elements.append(Switch("SW2"))
    # 4
    network_elements.append(Switch("SW3"))

    network_elements[0].network_layer.update({"RJ-45": network_elements[2]})
    network_elements[1].network_layer.update({"RJ-45": network_elements[2]})

    network_elements[2].network_layer.update({"Ethernet 1": network_elements[0]})
    network_elements[2].network_layer.update({"Ethernet 2": network_elements[1]})
    network_elements[2].network_layer.update({"Ethernet 3": network_elements[3]})
    network_elements[3].network_layer.update({"Ethernet 1": network_elements[2]})
    network_elements[3].network_layer.update({"Ethernet 2": network_elements[4]})
    network_elements[4].network_layer.update({"Ethernet 1": network_elements[3]})



    for i in range(len(network_elements)):
        print(f" --- --- {i+1} --- ---")
        print(network_elements[i].print_all_data())
        print(f"List of next nodes: {network_elements[i].next_nodes}")
        print("-"*100)

        paths = find_all_paths(network_elements[0], network_elements[4])
        for i, path in enumerate(paths, start=1):
            print(f"Path {i}: {' -> '.join([node.hostname for node in path])}")


def find_all_paths(start_node, end_node, path=None):
    """
    Находит все пути между start_node и end_node без повторений.
    :param start_node: Начальный узел (объект устройства).
    :param end_node: Конечный узел (объект устройства).
    :param path: Текущий путь (используется для рекурсии).
    :return: Список всех путей (каждый путь — список узлов).
    """
    if path is None:
        path = []

    # Добавляем текущий узел в путь
    path = path + [start_node]

    # Если достигли конечного узла, возвращаем текущий путь
    if start_node == end_node:
        return [path]

    # Если у текущего узла нет связей, возвращаем пустой список
    if not hasattr(start_node, "next_nodes") or not start_node.next_nodes:
        return []

    # Рекурсивно ищем пути через соседние узлы
    paths = []
    for node in start_node.next_nodes:
        if node not in path:  # Избегаем циклов
            new_paths = find_all_paths(node, end_node, path)
            for new_path in new_paths:
                paths.append(new_path)

    return paths


if __name__ == "__main__":
    main()