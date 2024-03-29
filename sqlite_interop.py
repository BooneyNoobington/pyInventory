# Create a database if it doesn't already exists.
def create_new_db(database_path, creation_script):
    import os
    import sqlite3

    # Check wether the database file already exists.
    if not os.path.exists(database_path):
        # Even if it doesn't exist, you can already connect to it.
        connection_db_creation = sqlite3.connect(database_path)

        # Execute the instruction in this file.
        try:  # The file can be corrupt.
            with open(creation_script, "r") as creation_statement:
                connection_db_creation.executescript(creation_statement.read())
        except Exception as e:
            print(f"Error creating datbase: {e}. Aborting script ...")
            import sys
            sys.exit(1)  # Exit with error.

        # It seems safer to close the database here.
        connection_db_creation.commit()
        connection_db_creation.close()




# Function to turn python datatypes into SQLite ones.
def suggest_type(var):
    import datetime  # Determination of datatype.
    # Catch unforseen problems.
    try:
        # Determine the datatype of var and
        # suggest a corresponding datatype in SQLite.
        if isinstance(var, int):
            return "INTEGER"
        elif isinstance(var, float):
            return "REAL"
        elif isinstance(var, str):
            return "TEXT"
        elif isinstance(var, bool):
            return "BOOLEAN"
        elif isinstance(var, datetime.datetime):
            return "NUMERIC"
        # Turn anything unknown or undefined into simple TEXT.
        else:
            return "TEXT"
    except Exception as e:
        print(f'Warning: Could not determine type of variable. Using TEXT. ({e}).')
        return "TEXT"



# Export the results of a query to a spreadsheet.
def export_to_spreadsheet(cursor, statement, spreadsheet_file):
    # Use tqdm to display a progress bar.
    import tqdm
    # Execute the statement and fetch the results.
    cursor.execute(statement)
    num_rows =cursor.rowcount  # Get total number of results.

    # Build the table that should be exported in memory as a tuple.
    # Use the cursor to get column headers (cursor.description).
    sheet = [tuple([i[0] for i in cursor.description])]

    # Depending on the file extension use different logic to export.
    if spreadsheet_file.endswith(".ods"):
        import pyexcel_ods
        # Straigtforward for Open Document format.
        # Initialize a progress bar object.
        with tqdm.tqdm(total=num_rows, desc="Export progress") as progress_bar:
            # Repeat indefinetly.
            while True:
                # Get a single line of the queries result.
                row = cursor.fetchone()
                # Sooner or later all result rows will be fetched.
                if not row: break  # Break the loop.
                # In every iteration the results row needs to be appended to the worksheet.
                sheet.append(row)
                # Append the changed sheet to excel file.
                pyexcel_ods.save_data(spreadsheet_file, {"Inventurergebnisse": sheet})
                # Update the progress bar with one (because one line was processed).
                progress_bar.update(1)

    elif spreadsheet_file.endswith(".xlsx") or spreadsheet_file.endswith(".xls"):
        # Shame the user for using obsolete file formats.
        if spreadsheet_file.endswith(".xlsx"):
            print("1998 called. They want their file format back…")
        # Use openpyxl package for export to excel.
        import openpyxl
        # Create a new workbook. TODO: Pretty much the same as the "sheet" tuple.
        workbook = openpyxl.Workbook()
        # Have this workbook choose an active sheet / tab.
        workbook_sheet = workbook.active
        # Fill it with column headers first.
        workbook_sheet.append([i[0] for i in cursor.description])
        while True:
            row = cursor.fetchone()
            if not row:
                break
            workbook_sheet.append(row)
        # Finally the actual export.
        workbook.save(spreadsheet_file)

    else:
        unknown_extension = spreadsheet_file.split('.')[-1].lower()
        print(f"No export logic for {unknown_extension}.")



# Check if a given database has the correct buildup. That means
# - All tables are there.
# - All columns exist.
# - Tables that can't be NULL have a NOT NULL constraint.
# - For SQLite the type can be ingored. TODO: Make this an option.
def check_database_buildup(cursor, creation_script, debug=False):
    import re
    # Open the database script fist.
    with (open(creation_script)) as f:
        creation_statement = f.read()

    pattern = re.compile(r'CREATE TABLE IF NOT EXISTS? [`"]?(\w+)[`"]?\s*\(', re.IGNORECASE)

    # Get all tables from that statement.
    required_tables = pattern.findall(creation_statement)

    # Get all tables that actually exist.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    actual_tables = cursor.fetchall()
    # Flatten the list-
    actual_tables = [item for sublist in actual_tables  for item in sublist]

    # Remove "system tables" like tables about the schema.

    if actual_tables == required_tables:
        if debug: print("All required tables exist.")
        return True
    else:
        print("Not all tables exist in the SQLite database. These are missing:")
        print(set(required_tables) - set(actual_tables))
        return False
