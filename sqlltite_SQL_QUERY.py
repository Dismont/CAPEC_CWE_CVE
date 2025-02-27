import sqlite3
from typing import Any

class CapecCweCve:

    def __init__(self, file:str):
        self.file = file
        self.connection = sqlite3.connect(file)
        self.cursor = self.connection.cursor()


    def create_table_capec(self) -> None:
            """ create table `CAPEC`

            (
                - id INT AUTOINCREMENT UNIQUE NOT NULL,
                - capec_id INT UNIQUE NOT NULL,
                - capec_name VARCHAR(100) NOT NULL,
                - capec_description TEXT NOT NULL,
                - capec_type VARCHAR(40) NOT NULL
            );
            :param self:
            :return:        None
            """
            try:
                self.cursor.execute("""
                create table IF NOT EXISTS `CAPEC`(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capec_id INTEGER NOT NULL UNIQUE,
                capec_name VARCHAR(150) NOT NULL UNIQUE,
                capec_description TEXT NOT NULL,
                capec_link VARCHAR(55) NOT NULL UNIQUE,
                capec_type VARCHAR(50) NOT NULL
                ); """)
            except Exception as e:
                print(f"Error: {e}")
            else:
                print("Таблица `CAPEC` создана!")
                self.connection.commit()

    def create_table_capec_parentof(self) -> None:
            """ create table `CAPEC_parentof`

             create table IF NOT EXISTS `CAPEC_parentof`
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capec_parent INTEGER NOT NULL,
                capec_child INTEGER NOT NULL
            );
            :return:        None
            """
            try:
                self.cursor.execute("""
                create table IF NOT EXISTS `CAPEC_parentof`(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capec_parent INTEGER NOT NULL,
                capec_child INTEGER NOT NULL
                ); """)
            except Exception as e:
                print(f"Error: {e}")
            else:
                print("Таблица `CAPEC_parentof` создана!")
                self.connection.commit()

    def create_table_capec_to_cwe(self) -> None:
            """ create table `CAPEC_to_CWE`

             create table IF NOT EXISTS `CAPEC_to_CWE`
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capec_id INTEGER NOT NULL,
                cwe_id INTEGER NOT NULL
            );

            :return:        None
            """
            try:
                self.cursor.execute("""
                create table IF NOT EXISTS `CAPEC_to_CWE` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capec_id INTEGER NOT NULL,
                cwe_id INTEGER NOT NULL
                );""")
            except Exception as e:
                print(f"Error: {e}")
            else:
                print("Таблица `CAPEC_to_CWE` создана!")
                self.connection.commit()



    def dropper_capec(self) -> None:
            """DROP TABLE `CAPEC`;

            :return:        None
            """

            try:
                self.cursor.execute("""
                DROP TABLE `CAPEC`;
                """)
            except Exception as e:
                print(f"Error: {e}")
            else:
                print("Таблица `CAPEC` УДАЛЕНА !")
                self.connection.commit()



    def insert_into_capec(self,*, data:str) -> None:

        i = 0
        try:
            text = ""
            with open(data, "r") as file:
                lines = file.readlines()
                file.close()


            for i in range(1,len(lines)):
                self.cursor.execute(f"{lines[0]} {lines[i].replace("),", ");")}")

        except Exception as e:
            print(f"Строка: {i}")
            print(f"Error : {e}")

        else:
            self.connection.commit()
            print(f"Таблица `CAPEC` заполнена\n - Использовалось: {data}")

    @staticmethod
    def bruter_file(*,data:str):

        with open(data,"r") as file:
            lines = file.readlines()

        text = []
        fix = []

        for i in range(len(lines)):
            if lines[i] not in text:
                text.append(lines[i])
            else:
                fix.append({"DELETE Row" : i})

        print("--- --- --- --- FIX --- --- --- --- ")
        print(*fix, sep="\n")

        with open(f"{data.replace(".sql","")}_fix.sql","a") as file:
            for i in range(len(text)):
                file.write(text[i])










def main():
    db = CapecCweCve("CAPEC_CWE_CVE.db")

# --- --- --- --- --- CREATOR --- --- --- --- --- --- ---

#  create `CAPEC` IF NOT EXISTS ✔
    # db.create_table_capec()

# create `CAPEC_parentof` IF NOT EXISTS ✔
    # db.create_table_capec_parentof()

# create table `CAPEC_to_CWE` IF NOT EXISTS ✔
    # db.create_table_capec_to_cwe()

# --- --- --- --- --- INSERTER --- --- --- --- --- --- ---

# insert `CAPEC`
    # db.bruter_file(data="SQL QUERY/INSERT_capec_ENTITY_query.sql")
    db.insert_into_capec(data="SQL QUERY/INSERT_capec_ENTITY_query_fix.sql")
# --- --- --- --- --- DROPPER --- --- --- --- --- --- ---

# !!! DROPER `CAPEC`
    # dropper_capec(connect=connection,cursor=cursor)

# =======================================================================================================




if __name__ == "__main__":
    main()

