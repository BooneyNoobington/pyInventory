INSERT INTO     `result`
                (
                    `id_scan`
                  , `filepath`
                  , `size`
                  , `id_filetype`
                  , `id_user`
                  , `id_group`
                  , `permissions`
                  , `creation_date_timestamp`
                  , `creation_date`
                  , `modification_date_timestamp`
                  , `modification_date`
                )
VALUES          (?,?,?,?,?,?,?,?,?,?,?)  -- Given by the script.
