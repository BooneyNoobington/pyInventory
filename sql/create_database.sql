-- Most interesting table.
-- The actual scan result.
CREATE TABLE IF NOT EXISTS "result" (
    "id_result" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  ,	"id_scan" INTEGER NOT NULL  -- Foreign key to remember which scan produced the result.
  ,	"filepath" TEXT NOT NULL  -- Just the filepath that was scanned.
  ,	"size" REAL NOT NULL  -- How big was the file?
  , "file_type" TEXT  -- Optional result.
  ,	"owner" TEXT NOT NULL  -- Who owns the file?
  ,	"group" TEXT NOT NULL  -- To which group does it belong? (Bogus value on Windows.)
  ,	"creation_date_timestamp" REAL NOT NULL  -- When was it created?
  ,	"creation_date" TEXT NOT NULL  -- Same in readable format.
  ,	"modification_date_timestamp" REAL NOT NULL  -- When was it mofified?
  ,	"modification_date" TEXT NOT NULL  -- Same in reable format.
  -- TODO: Maybe add access date? Not always on record.
  , FOREIGN KEY ("id_scan") REFERENCES "scan" ("id_scan")  -- Link to the scan.
);
-- A "meta data" table.
CREATE TABLE IF NOT EXISTS "scan" (
	"id_scan" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT  -- Running number.
  ,	"target" TEXT NOT NULL  -- Which directory was the target for the scan?
  ,	"scan_start" TEXT NOT NULL  -- When was the scan iniated? (This time just as readable value.)
  , "scan_stop"	TEXT NOT NULL  -- Same.
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
