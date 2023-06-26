#!/usr/bin/env python3

# Main function.
def main():

    import scan_comparison_functions as f  # Helper functions.

    # Use argparse to handle command line arguments.
    # Setup command line arguments.
    import argparse
    parser = argparse.ArgumentParser(
        description = "Compare to scans from the same or different  databases."
    )

    # Positional argument 1 is the first database. (The order is not important.)
    parser.add_argument(
          'database1'
        , metavar = 'database1'
        , type = str
        , help = 'path to first database'
    )

    # Positional argument 2 is the second database.
    parser.add_argument(
          'database2'
        , metavar = 'database2'
        , type = str
        , help = 'patht to second database'
    )

    # Every database can contain multiple scan runs. This option can specify one.
    # Default is always the latest.
    parser.add_argument(
          '--scan1'
         , type = int
        , default = None
        , help = 'give debug info about the scan (first database).'
    )

    # Every database can contain multiple scan runs. This option can specify one.
    # Default is always the latest.
    parser.add_argument(
          '--scan2'
        , type = int
        , default = None
        , help = 'give debug info about the scan (second database).'
    )

    # Option to provide debug output.
    parser.add_argument(
          '--debug'
        , action = 'store_true'
        , default = False
        , help = 'give debug info about the scan.'
    )

    # Store the result of this query into a sort of dictianory.
    args = parser.parse_args()

    # Load the databases into dicts.
    results_1 = f.open_database(args.database1, args.scan1, args.debug)
    results_2 = f.open_database(args.database2, args.scan2, args.debug)

    # Create a set of dictionaries from the results.
    results_set_1 = set(tuple(d.items()) for d in results_1)
    results_set_2 = set(tuple(d.items()) for d in results_2)

    # Find the difference between the sets
    difference_1_2 = [dict(t) for t in list(results_set_1 - results_set_2)]
    difference_2_1 = [dict(t) for t in list(results_set_2 - results_set_1)]

    # Determine what happend to the files.
    # Three things are monitored:
    # - A file has been deleted (or moved)
    # - A file has was created (or moved)
    # - A files contents have changed in some manner.
    # TODO: Track possible file movements using hashes.

    # Deletion and changes in content can be derived from looking at the
    # set difference of 1 minus 2.
    for i, diff in enumerate(difference_1_2):
        # Check if the filename appears in "results_2".
        if any(d.get("rel_path") == diff["rel_path"] for d in results_2):
            # If the file exists, but there was a difference detected,
            # its content might have changed.
            # Get info about the change candidate first.
            changed_file = [d for d in results_2 if d.get("rel_path") == diff["rel_path"]][0]
            # Compare hashes.
            if diff["xxhash"] != changed_file["xxhash"]:
                difference_1_2[i]["change"] = "File contents changed."
            # Compare modification dates:
            elif diff["modification_date"] != changed_file["modification_date"]:
                difference_1_2[i]["change"] = "Modification date changed but file contents did not."
            # Catch all clause if no change can be determined.
            else:
                difference_1_2[i]["change"] = "Undeterminable (false alarm?)"
        # If the filename doesn't appear in the second scan, it vanished / was deleted.
        else:
            f = diff["rel_path"]
            difference_1_2[i]["change"] = "File deleted or moved."

    # File creations can be monitored by looking at the set difference 2 minus 1.
    new_files = []
    for i, diff in enumerate(difference_2_1):
        # Check wether there is a file that exists in 2 but not in one.
        if not any(d.get("rel_path") == diff["rel_path"] for d in results_1):
            difference_2_1[i]["change"] = "File created or moved."
            new_files.append(difference_2_1[i])

    # If the list is empty, nothing has changed.
    if difference_1_2 == [] and difference_2_1 == []:  # Emtpy list / set.
        print("No difference detected.")
    else:
        import prettytable

        # Extract the headers.
        headers = [k for k in difference_1_2[0].keys()]

        # Initialize a new table.
        table = prettytable.PrettyTable(headers)

        # Loop over all the items in the difference list and fill the table with it.
        for item in difference_1_2:
            row = [v for v in item.values()]
            table.add_row(row)

        for item in new_files:
            row = [v for v in item.values()]
            table.add_row(row)

        print(table)



# Execute main.
if __name__ == '__main__':
    main()
