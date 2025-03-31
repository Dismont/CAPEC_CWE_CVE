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

    # ---------------------------------------------------------------------------------------------------

    def create_table_cwe(self) -> None:
        """create table `CWE`

            (
                - id INT AUTOINCREMENT UNIQUE NOT NULL,
                - cwe_id INT UNIQUE NOT NULL,
                - cwe_name VARCHAR(100) NOT NULL,
                - cwe_description TEXT NOT NULL,
                - cwe_type VARCHAR(40) NOT NULL
            );
        :param self:
        :return:        None
        """
        try:
            self.cursor.execute("""
                       create table IF NOT EXISTS `CWE`(
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       cwe_id INTEGER NOT NULL UNIQUE,
                       cwe_name VARCHAR(150) NOT NULL UNIQUE,
                       cwe_description TEXT NOT NULL,
                       cwe_link VARCHAR(55) NOT NULL UNIQUE,
                       cwe_type VARCHAR(50) NOT NULL
                       ); """)
        except Exception as e:
            print(f"Error: {e}")
        else:
            print("Таблица `CWE` создана!")
            self.connection.commit()

    def create_table_cwe_parentof(self) -> None:

        try:
            self.cursor.execute("""
                              create table IF NOT EXISTS `CWE_parentof`(
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                              cwe_parent INTEGER NOT NULL,
                              cwe_child INTEGER NOT NULL
                              ); """)
        except Exception as e:
            print(f"Error: {e}")
        else:
            print("Таблица `CWE_parentof` создана!")
            self.connection.commit()

    def create_table_cwe_to_cve(self) -> None:
        try:
            self.cursor.execute("""
                              create table IF NOT EXISTS `CWE_to_CVE`(
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                              cwe_id INTEGER NOT NULL,
                              cve_id VARCHAR(50) NOT NULL
                              ); """)
        except Exception as e:
            print(f"Error: {e}")
        else:
            print("Таблица `CWE_to_CVE` создана!")
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

    def dropper_cwe_to_cve(self) -> None:
        try:
            self.cursor.execute(""" drop table `CWE_to_CVE`;""")
        except Exception as e:
            print(f"Error: {e}")
        else:
            print("Таблица `CWE_to_CVE` УДАЛЕННА!")
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

    def insert_into_cwe(self,*, data:str) -> None:

        i = 0

        text = ""
        with open(data, "r") as file:
            lines = file.readlines()
            file.close()



            for i in range(1,len(lines)):
                try:
                    self.cursor.execute(f"{lines[0]} {lines[i].replace("),", ");")}")
                except Exception as e:
                    print(f"Строка: {i}")
                    print(f"Error : {e}")
                    continue

            self.connection.commit()
            print(f"Таблица `CWE` заполнена\n - Использовалось: {data}")

    def insert_into_capec_to_cwe(self,*, data:str) -> None:
        i = 0

        text = ""
        with open(data, "r") as file:
            lines = file.readlines()
            file.close()

            for i in range(1, len(lines)):
                try:
                    self.cursor.execute(f"{lines[0]} {lines[i].replace("),", ");")}")
                except Exception as e:
                    print(f"Строка: {i}")
                    print(f"Error : {e}")
                    continue

            self.connection.commit()
            print(f"Таблица `CAPEC_to_CWE` заполнена\n - Использовалось: {data}")



    def select_join_capec_parentof(self) -> None:

        # id, caped_parent_id, caped_child_id
        # select CAPEC.id, CAPEC.id
        self.cursor.execute("""
        SELECT 
    parent.capec_name AS `Имя родителя`,
    child.capec_name AS `Имя наследника`
FROM 
    CAPEC_parentof
INNER JOIN 
    CAPEC AS parent
    ON CAPEC_parentof.capec_parent = parent.capec_id
INNER JOIN 
    CAPEC AS child
    ON CAPEC_parentof.capec_child = child.capec_id;     
        """)

        # Получаем все строки результатов
        rows = self.cursor.fetchall()

        # Выводим данные
        for row in rows:
            print(row)

    def select_all_cwe(self) -> None:

        self.cursor.execute(""" SELECT * FROM CWE;""")

        # Получаем все строки результатов
        rows = self.cursor.fetchall()

        # Выводим данные
        for row in rows:
            print(row)

    def select_join_cwe_parentof(self) -> None:
        self.cursor.execute("""
        select 
            parent.cwe_name as `Parent ID`,
            child.cwe_name as `Child ID` 
        FROM CWE_parentof
            inner join CWE as parent on
                parent.cwe_id = CWE_parentof.cwe_parent
            inner join CWE as child on 
                child.cwe_id = CWE_parentof.cwe_child;  
                """)

        # Получаем все строки результатов
        rows = self.cursor.fetchall()

        # Выводим данные
        for row in rows:
            print(row)




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

# create table `CWE` IF NOT EXISTS
    # db.create_table_cwe()

# create table `CWE_parentof` IF NOT EXISTS
#     db.create_table_cwe_parentof()

# create table `CWE_to_CVE` IF NOT EXISTS
    # db.create_table_cwe_to_cve()

# --- --- --- --- --- INSERTER --- --- --- --- --- --- ---

# insert `CAPEC`
    # db.bruter_file(data="SQL QUERY/INSERT_capec_ENTITY_query.sql")
    # db.insert_into_capec(data="SQL QUERY/INSERT_capec_ENTITY_query_fix.sql")

# insert `CAPEC_parentof`
    # db.bruter_file(data="SQL QUERY/INSERT_capec_parentof_query.sql")
    # db.insert_into_capec(data="SQL QUERY/INSERT_capec_parentof_query_fix.sql")

# insert `CWE`
    # db.bruter_file(data="SQL QUERY/INSERT_cwe_ENTITY_query.sql")
    # db.insert_into_cwe(data="SQL QUERY/INSERT_cwe_ENTITY_query_fix.sql")

# insert `CWE_parentof`
    # db.bruter_file(data="SQL QUERY/INSERT_cwe_parentof_query.sql")
    # db.insert_into_cwe(data="SQL QUERY/INSERT_cwe_parentof_query_fix.sql")

# insert `CAPEC_to_CWE`
    # db.bruter_file(data="SQL QUERY/INSERT_capec_to_cwe_query.sql")
    # db.insert_into_capec_to_cwe(data="SQL QUERY/INSERT_capec_to_cwe_query_fix.sql")

# insert `CWE_to_CVE`
    # db.bruter_file(data="SQL QUERY/INSERT_cwe_to_cve_query.sql")
    # db.insert_into_cwe(data="SQL QUERY/INSERT_cwe_to_cve_query_fix.sql")


# --- --- --- --- --- DROPPER --- --- --- --- --- --- ---

# !!! DROPER `CAPEC`
    # dropper_capec(connect=connection,cursor=cursor)

# !!! DROPPER `CWE_to_CVE`
    # db.dropper_cwe_to_cve()

# --- --- --- --- --- SELECT --- --- --- --- --- --- ---

# SELECT INNER JOIN (CAPEC_parentof)
    # db.select_join_capec_parentof()

# SELECT * FROM CWE
    # db.select_all_cwe()

# SELECT INNER JOIN (CWE_parentof)
    # db.select_join_cwe_parentof()
# =======================================================================================================

    # CLOSE CONNECTION DB
    db.connection.close()


if __name__ == "__main__":
    main()

