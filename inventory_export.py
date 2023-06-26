#!/usr/bin/env python3
import sqlite_interop as si  # Exporting function.
import argparse  # Read command line arguments.
import sqlite3  # Opening a database connection.
import os  # Reliably create file paths.



def main():
    # Setup command line arguments.
    parser = argparse.ArgumentParser(
        description = "Export a sqlite3 database in the pyInventory format to a spreadsheet."
    )

    # Positional argument 1 is the export file (sqlite3 database).
    parser.add_argument(
          "database_path"
        , metavar = "database_path"
        , type = str
        , help = "compatible sqlite database"
    )

    # Positional argument 2 is the spreadsheet file.
    parser.add_argument(
          "export_file"
        , metavar = "export_file"
        , type = str
        , help = "spreadsheet to be created"
    )

    # Store the result of this query into a sort of dictianory.
    args = parser.parse_args()

    # Open a connection to the databse.
    connection = sqlite3.connect(args.database_path)
    cursor = connection.cursor()

    # User Information.
    print(f"Exporting {args.database_path} to {args.export_file}.")

    # There is a function to do just that in sqlite_interop.
    # Feed it with a pre defined sqlite statement.
    export_sql_query = os.path.join(os.path.dirname(__file__), "./sql/EXPORT_TO_SPREADSHEET.SQL")

    with open(export_sql_query, "rb") as f:
        si.export_to_spreadsheet(cursor, f.read().decode("utf-8"), args.export_file)



# Execute.
if __name__ == "__main__":
    main()
