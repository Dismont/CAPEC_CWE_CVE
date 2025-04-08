import entity

def main():
    PC1 = entity.PersonalComputer()
    PC1.configuration.update({"Hostname": "PC1"})


    PC2 = entity.PersonalComputer()
    PC2.configuration.update({"Hostname": "PC2"})
    PC1.network_layer.update({"RJ-45": PC1})

    PC1.print_all_data()
    PC2.print_all_data()



if __name__ == "__main__":
    main()