/* Retrieve only the columns which don't change by user iteraction. */
SELECT                  SUBSTR(filepath, LENGTH(target) + (CASE WHEN SUBSTR(target, -1) = '/' THEN 1 ELSE 2 END)) AS "rel_path"
                      , r.modification_date
                      , h.hash_value AS "xxhash"
FROM                    `result` r
                JOIN    `hash` h
                ON      r.id_result = h.id_result
                JOIN    `scan` s
                ON      s.id_scan = r.id_scan
WHERE                   hash_algorithm = 'xxhash'  -- This hash is always computed.
                AND     r.id_scan {scan}
