/* Retrieve only the columns which don't change by user iteraction.
The specific scan was given. */
SELECT                  r.filepath
                      --, r.`size`
                      --, r.creation_date
                      , r.modification_date
                      --, h.hash_algorithm
                      , h.hash_value AS "xxhash"
FROM                    `result` r
                JOIN    `hash` h
                ON      r.id_result = h.id_result
WHERE                   hash_algorithm = 'xxhash'  -- This hash is always computed.
                AND     r.id_scan = {scan}
