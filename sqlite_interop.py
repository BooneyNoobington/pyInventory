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


# Function to test wether a record exists and return its id.
# This function assumes, that there is already a database conneciton established.
def test_record_existence(cursor, table, record, id_column = None):
    # TODO: Implement likeness statements.
    # TODO: Implement id_column autofind.
    if id_column is None:
        id_column = "id_" + table

    # Guess a basic query.
    query = f"SELECT {id_column} FROM {table} WHERE "
    # Use the keys as column names and the values as column values.
    for k, v in my_dict.items():
        query += f"{k} = '{v}' AND "
    query = query[:-5]  # remove the last 'AND'

    # Execute query.
    cursor.execute(query)

    # Get the id column value from that.
    id_value = cursor.fetchone()[0]


    return id_value
