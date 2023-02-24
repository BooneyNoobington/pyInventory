# Function to guess the owner of a file.
def get_owner(file_path):
    # Code is os specify in this case.
    import platform
    import os
    operating_system = platform.system()
    # What to do for each os.
    if operating_system == "Linux":
        # Use pwd to get user.
        import pwd
        uid = os.stat(file_path).st_uid
        account_name = pwd.getpwuid(uid).pw_name
    elif operating_system == "Windows":
        # It"s a little more complex on windows.
        import win32security
        # Initialze an object which contains security related info about a file.
        sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
        # Extract the owner id.
        uid = sd.GetSecurityDescriptorOwner()
        # Use it to retrieve the account name.
        account_name = win32security.LookupAccountSid(None, uid)[0]
        
        # Get the owner SID from the security descriptor
        owner_sid = sd.GetSecurityDescriptorOwner()
        # Convert the owner SID to a string representation
        uid = win32security.ConvertSidToStringSid(owner_sid)
    
    # Return both.
    return account_name, uid



# Function to guess the group of a file.
def get_group(file_path):
    # Code is os specific.
    import platform
    import os
    operating_system = platform.system()
    # No output for Windows. There"s no direct group equivalent there.
    if operating_system == "Windows":
        return "No goup on Windows ¯\_(ツ)_/¯", -1
    # Unixoide oses should do this:
    import grp  # Module for group name extraction.
    st = os.stat(file_path)  # General info about the file.
    gid = st.st_gid  # Gives group id.
    group_name = grp.getgrgid(gid).gr_name  # Can be translated to group name.
	
	# Return both.
    return group_name, gid



# Compute a checksum for a specific file.
# TODO: Add checksum options.
def checksum(file_path, algorithms = ["xxhash"]):  # By default only xxhash.
    checksums = []  # Empty list of all computed hashes.
    # Safeguard against file not found.
    # E.g. for dead symlinks.
    for a in algorithms:
        # Arm against file not found.
        with open(file_path, "rb") as f:
            # Code for various hashing algorithms.
            if a == "xxhash":
                import xxhash
                # Update the result list.
                checksums.append(
                    {"algorithm": a, "hash_value": xxhash.xxh64(f.read()).hexdigest()}
                )
            elif a == "md5":
                import hashlib
                # Initialze new md5 object.
                hash_md5 = hashlib.md5()
                # Some files are really big. Read them in chunks.
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)  # Update the hash with the next chunk of data.
                # Update the result list.
                checksums.append(
                    {"algorithm": a, "hash_value": hash_md5.hexdigest()}
                )
            else:
                print(f"Sorry. Hash type \"{a}\" not supported.")

    return checksums


# Print file information in a nice format.
# TODO: Very hardcody.
def print_file_info(file_info):
    file_path = file_info["file_path"]
    size = file_info["size"]
    owner = file_info["owner"]
    group = file_info["group"]
    file_type = file_info["file_type"]
    creation_date = file_info["creation_date"]
    modification_date = file_info["modification_date"]

    print("------------------------------------")
    print(f"Absolute file path: {file_path}")
    print(f"File size [kB]: {size}")
    print(f"Owned by: {owner}")
    print(f"Belongs in: {group}")
    print(f"File is of type: {file_type}")
    print(f"Created at: {creation_date}")
    print(f"Last modification at: {modification_date}")
    print("Hash algorithms and values:")
    import pprint
    pprint.pprint(file_info["hashes"])




# --- More complex, program specific functions.
# Gather information about a file.
def info_gathering(file_path, hashes, debug = False):

    import datetime  # Measure time and handle dates.
    if debug: print(f"Gathering info about {file_path}.")

    # Take the starting time.
    start_time = datetime.datetime.now()

    # Start with an empty dictianory and an empty list for logging errors.
    file_info = {}
    errors = []

    # First the path as quasi primary key.
    # Not much should go wrong here.
    file_info["file_path"] = file_path

    # Add info about size.
    try:
        import os
        file_info["size"] = os.path.getsize(file_path)
    except Exception as e:  # Filesize cannot be determined for some reason.
        message = f"Unable to determine file size of {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["size"] = -1

    # About the owner.
    try:
        file_info["owner"], file_info["uid"] = get_owner(file_path)
    except Exception as e:
        message = f"Unable to determine ownership of {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["owner"] = "Undetermineable (check errors)"
        file_info["uid"] = -1

    # About the group.
    try:
        file_info["group"], file_info["gid"] = get_group(file_path)
    except Exception as e:
        message = f"Unable to determine group membership of {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["group"] = "Undetermineable (check errors)"
        file_info["gid"] = -1

    # About the creation date of the file.
    try:
        file_info["creation_date_timestamp"] = os.path.getctime(file_path)
        file_info["creation_date"] = datetime.datetime.fromtimestamp(
            os.path.getctime(file_path)
        ).strftime("%Y.%m.%d %H:%M:%S")
    except Exception as e:
        message = f"Unable to creation date for {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["creation_date_timestamp"] = "Undetermineable (check errors)"
        file_info["creation_date"] = "Undetermineable (check errors)"

    # About the last time the file was modified.
    try:
        file_info["modification_date_timestamp"] = os.path.getmtime(file_path)
        file_info["modification_date"] = datetime.datetime.fromtimestamp(
            os.path.getmtime(file_path)
        ).strftime("%Y.%m.%d %H:%M:%S")
    except Exception as e:
        message = f"Unable to modification date for {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["modification_date_timestamp"] = "Undetermineable (check errors)"
        file_info["modification_date"] = "Undetermineable (check errors)"

    # Compute hashes.
    try:  # More likely to encounter an error here.
        file_info["hashes"] = checksum(file_path, hashes)
    except Exception as e:
        message = f"Unable to compute hashes for {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["hashes"] = [{"algorithm": "None", "hash_value": "Undetermineable"}]

    # Try and determine the file type.
    import filetype  # Guess the file type from magic bytes.
    try:
        if filetype.guess(file_path) is None:
            file_info["file_type"] = "Undetermineable"
        else:
            file_info["file_type"] = str(filetype.guess_mime(file_path))
    except Exception as e:
        message = f"Unable to guess the file type of {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["file_type"] = "Undetermineable"

    # Try and get the permissions.
    try:
        # Transfer to octal.
        file_info["permissions"] = oct(os.stat(file_path).st_mode)[-3:]  # Grab the last three digits.
    except Exception as e:
        message = f"Unable to determine the permissions of {file_path}. {e}."
        print(message)
        errors.append(message)
        file_info["permissions"] = -1

    # Take the stop time.
    stop_time = datetime.datetime.now()
    # Calculate the time difference.
    time_difference = stop_time - start_time
    # Write these three values in the file_info dict.
    file_info["start_time"] = start_time.strftime("%Y.%m.%d %H:%M:%S")
    file_info["stop_time"] = stop_time.strftime("%Y.%m.%d %H:%M:%S")
    file_info["time_difference"] = time_difference.total_seconds()

    # Add the errors to the file_info dictianory.
    file_info["errors"] = errors

    # Return the dictianory.
    return file_info


# Walk through a directory recursively.
def walk_dir(dir_path, dots, hashes, debug):
    # Again arm yourself against file not found errors.
    file_data = []  # Initialize an empty list.
    # Actual walk. Process directories and files alike.
    import os  # To walk dirs and safely create paths.
    for root, dirs, files in os.walk(dir_path, followlinks = True):
        if not dots:  # Do not include hidden directories.
            # Re-evaluate the dirctories list to omit dirs starting with a dot.
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            # Process files.
        for f in files:
            # Build a complete absolute path.
            file_path = os.path.join(root, f)
            if not dots:  # Do not include hidden files.
                if not f.startswith("."):
                    try:
                        file_data.append(info_gathering(file_path, hashes, debug))
                    except FileNotFoundError:
                        print(f"The file \"{f}\" was not found.")  # Do nothing when file is missing.
                    except Exception as e:
                        print(f"Other Error while trying to gather file info. {e}.")
            else:  # DO include hidden files.
                try:
                    file_data.append(info_gathering(file_path, hashes, debug))
                except FileNotFoundError:
                    print(f"The file \"{f}\" was not found.")  # Do nothing when file is missing.
                except Exception as e:
                    print(f"Other Error while trying to gather file info. {e}.")
    # when all of this is finished, return the filled dictianory.
    return file_data
