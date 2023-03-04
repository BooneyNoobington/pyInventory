SELECT 				r.`filepath` AS "Dateipfad"
				  , r.`size` AS "Dateigröße [Byte]"
				  , u.`user_name` AS "Eigentümer"
				  , g.`group_name` AS "Gruppenzugehörigkeit"
				  , r.`creation_date` AS "Erstellt am"
				  , r.`modification_date` AS "Zuletzt verändert am"
				  , h.`hash_value` AS "xxHash-Wert"
FROM				`result` r
			JOIN	`hash` h
			ON		h.id_scan = r.id_scan AND h.id_result = r.id_result
			JOIN	`user` u
			ON		u.id_user = r.id_user
			JOIN	`group` g
			ON		g.id_group = r.id_group
WHERE				h.`hash_algorithm` = 'xxhash'			