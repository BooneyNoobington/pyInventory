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
