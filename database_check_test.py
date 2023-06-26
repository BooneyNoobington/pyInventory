#!/usr/bin/env python3

import argparse
import sqlite3
import sqlite_interop as si



def main():
    connection = sqlite3.connect("/home/grindel/Schreibtisch/Inventurtest.db")
    cursor = connection.cursor()
    si.check_database_buildup(cursor, "/home/grindel/Entwicklung/pyInventory/sql/CREATE_DATABASE.SQL", True)



if __name__ == "__main__":
    main()
