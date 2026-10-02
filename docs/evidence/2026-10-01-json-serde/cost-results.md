| input | bytes | old ms | old peak | old outcome | Value ms | Value peak | Value outcome | raw ms | raw peak | raw outcome |
|---|---:|---:|---:|---|---:|---:|---|---:|---:|---|
| long integer | 196606 | 0.07 | 30 | err(number too long) | 0.06 | 185 | err(number out of range) | 0.05 | 465 | ok(1) |
| long fraction | 196605 | 0.05 | 30 | err(number too long) | 0.06 | 641 | ok(1) | 0.05 | 465 | ok(1) |
| long exponent | 196605 | 0.05 | 30 | err(number too long) | 0.00 | 185 | err(number out of range) | 0.06 | 465 | ok(1) |
| long name | 196603 | 0.17 | 196597 | err(member name too long) | 0.02 | 197237 | ok(1) | 0.02 | 197061 | ok(1) |
| long string | 196605 | 0.10 | 196837 | ok(1) | 0.02 | 197238 | ok(1) | 0.02 | 465 | ok(1) |
| escaped string | 196604 | 0.20 | 98312 | ok(1) | 0.20 | 131701 | ok(1) | 0.08 | 465 | ok(1) |
| array of 0 | 196607 | 0.61 | 240 | ok(1) | 1.73 | 6291457 | ok(1) | 0.25 | 465 | ok(1) |
| array of {} | 196606 | 0.31 | 240 | ok(1) | 1.63 | 3145729 | ok(1) | 0.16 | 465 | ok(1) |
| array of [] | 196606 | 0.28 | 240 | ok(1) | 1.75 | 3145729 | ok(1) | 0.16 | 465 | ok(1) |
| array of "" | 196606 | 0.89 | 2359304 | ok(1) | 1.13 | 3145729 | ok(1) | 0.30 | 465 | ok(1) |
| distinct members | 196603 | 1.20 | 2883592 | ok(22330) | 3.40 | 2455560 | ok(22330) | 3.61 | 1809112 | ok(22330) |
| one name repeated | 196603 | 1.69 | 2883592 | ok(32767) | 1.16 | 641 | ok(1) | 0.97 | 465 | ok(1) |
| array of {"":0} | 196602 | 0.50 | 240 | ok(1) | 7.12 | 18798937 | ok(1) | 0.32 | 465 | ok(1) |
| 63-deep objects x many | 196487 | 0.51 | 240 | ok(1) | 9.98 | 24706689 | ok(1) | 0.28 | 521 | ok(1) |
| 3 MiB deep | 196606 | 0.00 | 78 | err(nesting deeper than 64) | 0.00 | 172 | err(recursion limit exceeded) | 0.24 | 196609 | ok(1) |
| lone surrogate | 14 | 0.00 | 248 | ok(1) | 0.00 | 192 | err(unexpected end of hex escape) | 0.00 | 465 | ok(1) |
| 127-deep objects x many | 196258 | 0.00 | 78 | err(nesting deeper than 64) | 9.64 | 24744025 | ok(1) | 0.27 | 585 | ok(1) |
| 127 deep x many | 196540 | 0.00 | 78 | err(nesting deeper than 64) | 8.83 | 12461185 | ok(1) | 0.26 | 585 | ok(1) |
| long integer | 3145726 | 1.16 | 30 | err(number too long) | 1.02 | 185 | err(number out of range) | 0.77 | 465 | ok(1) |
| long fraction | 3145725 | 0.92 | 30 | err(number too long) | 1.08 | 641 | ok(1) | 0.79 | 465 | ok(1) |
| long exponent | 3145725 | 0.77 | 30 | err(number too long) | 0.00 | 185 | err(number out of range) | 1.04 | 465 | ok(1) |
| long name | 3145723 | 2.92 | 3145717 | err(member name too long) | 0.75 | 3146357 | ok(1) | 0.75 | 3146181 | ok(1) |
| long string | 3145725 | 1.79 | 3145957 | ok(1) | 0.74 | 3146358 | ok(1) | 0.45 | 465 | ok(1) |
| escaped string | 3145724 | 3.25 | 1572872 | ok(1) | 3.40 | 2097781 | ok(1) | 1.34 | 465 | ok(1) |
| array of 0 | 3145727 | 9.70 | 240 | ok(1) | 49.18 | 100663297 | ok(1) | 4.01 | 465 | ok(1) |
| array of {} | 3145726 | 4.65 | 240 | ok(1) | 43.91 | 50331649 | ok(1) | 2.58 | 465 | ok(1) |
| array of [] | 3145726 | 4.50 | 240 | ok(1) | 46.13 | 50331649 | ok(1) | 3.36 | 465 | ok(1) |
| array of "" | 3145726 | 22.13 | 37748744 | ok(1) | 27.73 | 50331649 | ok(1) | 6.73 | 465 | ok(1) |
| distinct members | 3145727 | 26.26 | 46137352 | ok(321563) | 89.26 | 35729679 | ok(321563) | 82.93 | 26407311 | ok(321563) |
| one name repeated | 3145723 | 41.31 | 46137352 | ok(524287) | 24.21 | 641 | ok(1) | 20.75 | 465 | ok(1) |
| array of {"":0} | 3145723 | 10.66 | 240 | ok(1) | 205.32 | 300791073 | ok(1) | 6.85 | 465 | ok(1) |
| 63-deep objects x many | 3145529 | 10.61 | 240 | ok(1) | 252.26 | 395528721 | ok(1) | 5.78 | 521 | ok(1) |
| 3 MiB deep | 3145726 | 0.00 | 78 | err(nesting deeper than 64) | 0.01 | 172 | err(recursion limit exceeded) | 5.41 | 3145729 | ok(1) |
| lone surrogate | 14 | 0.00 | 248 | ok(1) | 0.00 | 192 | err(unexpected end of hex escape) | 0.00 | 465 | ok(1) |
| 127-deep objects x many | 3145666 | 0.00 | 78 | err(nesting deeper than 64) | 289.37 | 396605785 | ok(1) | 4.36 | 585 | ok(1) |
| 127 deep x many | 3145539 | 0.00 | 78 | err(nesting deeper than 64) | 240.42 | 199432833 | ok(1) | 5.48 | 585 | ok(1) |
