#!/usr/bin/env python3

# Open a scanning database.
def open_database(db_path, scan, debug = False):
    import sqlite3  # Connect to database.

    # Connect to the database
    db_connection = sqlite3.connect(db_path)
    cursor = db_connection.cursor()

    # Some minor details differ for various platforms.
    #import platform
    #if platform.system() == "Windows":
    #    length_modificator = 3
    #else:
    #    length_modificator = 2

    import os  # Safely create paths.
    # Execute the query.
    with open(os.path.join(os.path.dirname(__file__), "./sql/DATABASE_TO_DICT.SQL"), "r") as f:
        if scan is None:
            # When no scan was specified, select the latest one.
            query = f.read().format(scan = "IN (SELECT MAX(ID_SCAN) FROM `scan`)")
        # Otherwise use the specified one.
        else:
            query = f.read().format(scan = " = " + str(scan))  # Replace the specific scan.

    if debug: print(query)

    # Execute the query previously defined.
    cursor.execute(query)

    # Fetch the results
    rows = cursor.fetchall()

    # Warn user if result set is empty.
    if rows == []: print(f"Warning. No results for this query: \n{query}")

    # Convert the result into a list of dictionaries
    column_names = [c[0] for c in cursor.description]
    result = [dict(zip(column_names, row)) for row in rows]

    # Close the connection
    db_connection.close()

    # Return the result.
    return result
