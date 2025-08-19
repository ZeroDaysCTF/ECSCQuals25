## Writeup

The text on the image is written in the Dovahzul Language. You can translate it selecting the corresponding glyphs at:
https://www.dcode.fr/dovahzul-dragon-language

**Raw Glyphs**
```char(87)char(72)char(79)char(68)char(69)char(67)char(73)char(68)char(69)char(68)char(84)char(72)char(65)char(84)char(84)char(72)char(73)char(83)char(73)char(83)char(65)char(71)char(56)char(68)char(80)char(65)char(83)char(83)char(87)char(79)char(82)char(68)```

Once you do you get the string: WHODECIDEDTHATTHISISAGOODPASSWORD

This is the password for Steghide. Using this you can get the next file `Theyre_heeere.txt`. This file is seemingly blank with only whitespace.
The name of the file is a hint. The quote is from Poltergiest, and the file is encoded in Poltergiest:
https://github.com/Shell-Company/poltergeist

You can use this tool to decode the whitespace:
```
poltergeist -decode -file Theyre_heeere.txt
ZeroDays{sp00ky_sc4ry_gh0sts_hiDinG_mY_flagz}
```
