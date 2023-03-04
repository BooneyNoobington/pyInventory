-- Most interesting table.
-- The actual scan result.
CREATE TABLE IF NOT EXISTS "result" (
    "id_result" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  ,	"id_scan" INTEGER NOT NULL  -- Foreign key to remember which scan produced the result.
  ,	"filepath" TEXT NOT NULL  -- Just the filepath that was scanned.
  ,	"size" INTEGER NOT NULL  -- How big was the file?
  , "id_filetype" INTEGER  -- Optional result.
  ,	"id_user" INTEGER NOT NULL  -- Who owns the file?
  ,	"id_group" INTEGER NOT NULL   -- To which group does it belong? (Bogus value on Windows.)
  , "permissions" INTEGER NOT NULL  -- What permissions does the file have?
  ,	"creation_date_timestamp" REAL -- When was it created?
  ,	"creation_date" TEXT NOT NULL  -- Same in readable format.
  ,	"modification_date_timestamp" REAL -- When was it mofified?
  ,	"modification_date" TEXT NOT NULL  -- Same in reable format.
  -- TODO: Maybe add access date? Not always on record.
  , FOREIGN KEY ("id_scan") REFERENCES "scan" ("id_scan")  -- Link to the scan.
  , FOREIGN KEY ("id_filetype") REFERENCES "filetype" ("id_filetype")  -- Link to filetype.
  , FOREIGN KEY ("id_user") REFERENCES "user" ("id_user")  -- Link to user name.
  , FOREIGN KEY ("id_group") REFERENCES "group" ("id_group")  -- Link to group name.
);
-- A table for all known file formats.
CREATE TABLE IF NOT EXISTS "filetype" (
    "id_filetype" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  , "filetype" TEXT NOT NULL  -- Description of the file type.
);
-- A table to log all users of the scanned files.
CREATE TABLE IF NOT EXISTS "user" (
    "id_user" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  , "user_name" TEXT NOT NULL  -- Acutal name of the user, e.g. on the terminal or on login.
  , "uid" INTEGER  -- Optional setting for user id.
);
-- A table to log all groups.
CREATE TABLE IF NOT EXISTS "group" (
    "id_group" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  , "group_name" TEXT NOT NULL  -- Readable name of the group.
  , "gid" INTEGER  -- Optional attribute for group.
);
-- A "meta data" table.
CREATE TABLE IF NOT EXISTS "scan" (
	"id_scan" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  ,	"target" TEXT NOT NULL  -- Which directory was the target for the scan?
  ,	"scan_start" TEXT NOT NULL  -- When was the scan iniated? (This time just as readable value.)
  , "scan_stop"	TEXT  -- Can be NULL. This would indicate a failed / incomplete scan.
);
-- Various hash values for the same result / file can be stored here.
CREATE TABLE IF NOT EXISTS "hash" (
	"id_hash" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  , "id_result" INTEGER NOT NULL  -- Link to specific result.
  , "id_scan" INTEGER NOT NULL  -- During which scan was this result produced.
  ,	"hash_algorithm" TEXT NOT NULL  -- What algorithm was used?
  ,	"hash_value" TEXT NOT NULL  -- What was the actual value?
  ,	FOREIGN KEY ("id_result") REFERENCES "result" ("id_result")
  , FOREIGN KEY ("id_scan") REFERENCES "scan" ("id_scan")
);
-- Error messages.
CREATE TABLE IF NOT EXISTS "error" (
    "id_error" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  , "id_scan" INTEGER
  , "id_result" INTEGER  -- Link to scanned file result.
  , "message" TEXT NOT NULL  -- An explaination what went wrong.
  , "error_code" INTEGER  -- If available, an error code.
  , FOREIGN KEY ("id_scan") REFERENCES "scan" ("id_scan")
  , FOREIGN KEY ("id_result") REFERENCES "result" ("id_result")
);
