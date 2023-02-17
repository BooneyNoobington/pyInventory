#!/usr/bin/env python3
import os  # Walking a directory.
import sqlite3  # Export the findings to a database.
import argparse  # Interpret command line arguments.
import datetime  # Get the current time.
import sqlite_interop as si  # SQLite specific functions.
import inventory_helpers as h  # Helper functions specific to this script.


# Main function.
def main():

    # Setup command line arguments.
    parser = argparse.ArgumentParser(
        description = 'Walk a directory and save file information to YAML file'
    )

    # Positional argument 1 is the directory to be walked.
    parser.add_argument(
          'dir_path'
        , metavar = 'dir_path'
        , type = str
        , help = 'directory path'
    )

    # Positional argument 2 is the export file (sqlite3 database).
    parser.add_argument(
          'database_path'
        , metavar = 'database_path'
        , type = str
        , help = 'output file path'
    )

    # Include hidden files? Default is not to.
    parser.add_argument(
          '--hidden'
        , action = 'store_true'
        , default = False
        , help = 'include hidden files and directories'
    )

    # Option to provide debug output.
    parser.add_argument(
          '--debug'
        , action = 'store_true'
        , default = False
        , help = 'give debug info about the scan.'
    )

    # Additional hashing algorithms. (You always get xxhash).
    parser.add_argument(
          '--md5'
        , action = 'store_true'
        , default = False
        , help = 'give debug info about the scan.'
    )

    # Store the result of this query into a sort of dictianory.
    args = parser.parse_args()

    # Extract additional hashes.
    hashes = ["xxhash"]
    if args.md5: hashes.append("md5")

    # Use the arguemnts.
    dir_path = args.dir_path
    database_path = args.database_path

    # Execute the search.
    start_time = datetime.datetime.now().strftime('%Y.%m.%d %H:%M:%S')
    file_data = h.walk_dir(dir_path, args.hidden, hashes, args.debug)
    stop_time = datetime.datetime.now().strftime('%Y.%m.%d %H:%M:%S')

    # Write data to database.
    print('Info gathering finished. Writing findings to database …')

    # If the database file doesn't exist already, creaste it.
    # Execute the SQL statements in the file
    import os
    if not os.path.exists(database_path):
        # Connect to the database (A different connection, just to create it.)
        # TODO: Neccessary to separate?
        connection_db_creation = sqlite3.connect(database_path)
        # Create a safe path pointing to the databse generation script.
        sql_sourcefile_path = os.path.join(os.path.dirname(__file__), 'sql/create_database.sql')

        # Execute the instruction in this file.
        try:  # The file can be corrupt.
            with open(sql_sourcefile_path, 'r') as sql_sourcefile:
                connection_db_creation.executescript(sql_sourcefile.read())
        except Exception as e:
            print(f"Error creating datbase: {e}. Aborting script ...")
            import sys
            sys.exit(1)  # Exit with error.

        # TODO: Maybe neccessary, maybe not...
        connection_db_creation.commit()
        connection_db_creation.close()


    # Connect to the database. For dropping results this time.
    connection = sqlite3.connect(database_path)

    # Initialize the cursor to the database.
    cursor = connection.cursor()

    # Insert metadata about the scan itself to the database.
    if args.debug: print("Noting that scan was executed.")
    cursor.execute(
        "INSERT INTO scan (target, scan_start, scan_stop) VALUES(?,?,?)"
      , (dir_path, start_time, stop_time)
    )

    # Grab the latest id.
    id_scan = cursor.lastrowid

    # Now enter all the results.
    for r in file_data:
        # Every entry gets its own row.
        if args.debug:
            h.print_file_info(r)
            print("Executing this query: (Quotes omitted)")
            values_string = str(r["file_path"]) + ", " + str(r["size"]) + ", " + str(r["owner"]) + ", " + str(r["group"]) + ", " + str(r["creation_date_timestamp"]) + ", " + str(r["creation_date"]) + ", " + str(r["modification_date_timestamp"]) + ", " + str(r["modification_date"])
            print(f"INSERT INTO result (id_scan, filepath, size, owner, group, creation_date_timestamp, creation_date, modification_date_timestamp, modification_date) VALUES ({values_string})")
        # Generate a new record.
        try:
            cursor.execute(
                "INSERT INTO result (id_scan, filepath, size, file_type, owner, `group`, creation_date_timestamp, creation_date, modification_date_timestamp, modification_date) VALUES (?,?,?,?,?,?,?,?,?,?)"
            , (id_scan, r["file_path"], r["size"], r["file_type"], r["owner"], r["group"], r["creation_date_timestamp"], r["creation_date"], r["modification_date_timestamp"], r["modification_date"])
            )
        except Exception as e:
            message = f"Sorry. Can't write info to database. {e}."
            print(message)
            cursor.execute(
                "INSERT INTO `error` (id_scan, message VALUES(?,?) )", (id_scan, message)
            )

        # Grab the last result id.
        id_result = cursor.lastrowid

        # Now loop over all the hashes.
        for hash_dict in r["hashes"]:
            cursor.execute(
                "INSERT INTO hash (id_result, id_scan, hash_algorithm, hash_value) VALUES(?,?,?,?)"
              , (id_result, id_scan, hash_dict["algorithm"], hash_dict["hash_value"])
            )

        # And loop over the errors.
        for error in r["errors"]:
            # TODO: Implement error codes.
            cursor.execute(
                "INSERT INTO `error` (id_scan, id_result, message) VALUES(?,?,?)"
              , (id_scan, id_result, error)
            )

    # Commit the changes and close the connection
    connection.commit()

    # When everything is done, close the connection.
    connection.close()




# Execute.
if __name__ == '__main__':
    main()
