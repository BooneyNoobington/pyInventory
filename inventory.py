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
        description = "Walk a directory and save file information to SQLite database"
    )

    # Positional argument 1 is the directory to be walked.
    parser.add_argument(
          "dir_path"
        , metavar = "dir_path"
        , type = str
        , help = "directory path"
    )

    # Positional argument 2 is the export file (sqlite3 database).
    parser.add_argument(
          "database_path"
        , metavar = "database_path"
        , type = str
        , help = "output file path"
    )

    # Include hidden files? Default is not to.
    parser.add_argument(
          "--hidden"
        , action = "store_true"
        , default = False
        , help = "include hidden files and directories"
    )

    # Option to provide debug output.
    parser.add_argument(
          "--debug"
        , action = "store_true"
        , default = False
        , help = "give debug info about the scan."
    )

    # Additional hashing algorithms. (You always get xxhash).
    parser.add_argument(
          "--md5"
        , action = "store_true"
        , default = False
        , help = "also compute md5 hashes of the files"
    )

    # Name for the scan.
    parser.add_argument(
          "--scan-name"
        , type = str
        , default = "Manual scan"
    )

    # Store the result of this query into a sort of dictianory.
    args = parser.parse_args()

    # Extract additional hashes.
    hashes = ["xxhash"]
    if args.md5: hashes.append("md5")

    # Use the arguemnts.
    dir_path = args.dir_path
    database_path = args.database_path

    # Call the inventorization function.
    inventorize(dir_path, database_path, hashes, args.hidden, args.debug, args.scan_name)



# Walk a directory and inventorize its contents.
def inventorize(dir_path, database_path, hashes, hidden, debug, scan_name):

    import inventory_helpers as h  # Various helper functions.
    import sqlite_interop as si  # SQLite connection.
    import os  # File creation.

    # Execute the search.
    start_time_dt = datetime.datetime.now()
    start_time = start_time_dt.strftime("%Y.%m.%d %H:%M:%S")
    if debug: print(f"DEBUG Started inventorization at {start_time}…")

    # If the database file doesn"t exist already, create it.
    si.create_new_db(
        database_path, os.path.join(os.path.dirname(__file__), "sql/CREATE_DATABASE.SQL")
    )

    # Connect to the database. Just for writing metadata about the scan.
    connection = sqlite3.connect(database_path)

    # Initialize the cursor to the database.
    cursor = connection.cursor()

    # Insert metadata about the scan itself to the database.
    if debug: print("DEBUG Writing information about specific scan to datbase.")
    cursor.execute(
        "INSERT INTO scan (target, scan_start, identifier) VALUES(?,?,?)"
      , (dir_path, start_time, scan_name)
    )

    # Grab the latest id.
    id_scan = cursor.lastrowid

    # Loop over all files and dirs and write the gathered information in the database.
    file_data = h.walk_dir(cursor, id_scan, dir_path, hidden, hashes, debug)

    # When your'e here, measure how long it took.
    stop_time_dt = datetime.datetime.now()
    stop_time = stop_time_dt.strftime("%Y.%m.%d %H:%M:%S")
    duration = stop_time_dt - start_time_dt
    if debug: print(
        f"DEBUG inventorization finished at {stop_time}. \n" +
        f"Duration: {duration}."
    )

    # Update the stop time of the scan.
    cursor.execute(
        "UPDATE `scan` SET `scan_stop` = ? WHERE `id_scan` = ?"
      , (stop_time, id_scan)
    )

    connection.commit()  # Commit the changes.
    connection.close()  # When everything is done, close the connection.




# Execute.
if __name__ == "__main__":
    main()
