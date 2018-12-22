# Hidden in almost plain sight

### X-MAS CTF 2018, Forensics [374]

> A strange file was sent to Santa's email address and he is puzzled. Help him find what's wrong with the file and you can keep any flag you find in the process.

Attached to the challenge was a (corrupted) file named `Celebration`.

Inspecting the first few bytes in a hex editor reveals the file type, and why the file is corrupted:

    $ xxd Celebration | head                     
    00000000: 8900 0047 0d0a 1a0a 0000 000d 4948 4452  ...G........IHDR
    00000010: 0000 15f0 0000 0cb2 0802 0000 00eb a6d7  ................
    00000020: 5f00 0000 0970 4859 7300 000e f300 000e  _....pHYs.......
    00000030: f301 1c53 993a 0000 0011 7445 5874 5469  ...S.:....tEXtTi
    00000040: 746c 6500 5044 4620 4372 6561 746f 7241  tle.PDF CreatorA
    00000050: 5ebc 2800 0000 1374 4558 7441 7574 686f  ^.(....tEXtAutho
    00000060: 7200 5044 4620 546f 6f6c 7320 4147 1bcf  r.PDF Tools AG..
    00000070: 7730 0000 002d 7a54 5874 4465 7363 7269  w0...-zTXtDescri
    00000080: 7074 696f 6e00 0008 99cb 2829 29b0 d2d7  ption.....())...
    00000090: 2f2f 2fd7 2b48 49d3 2dc9 cfcf 29d6 4bce  ///.+HI.-...).K.

The `IHDR`, `pHYs`, and `tEXt` markers show that this is a PNG file, albeit one that lacks the characteristic `PNG` magic byte sequence at the start of the file. Replacing the two NULs at the start of the file restores the image:

![The image after restoring the header](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/hidden-in-almost-plain-sight/images/restored-small.png)

Opening the image in any libpng-based image viewer (I used `sxiv`) will print a warning message:

    libpng warning: IDAT: Too much image data

The `unhide.py` script will increase the image height to use the entire `IDAT` data chunk:

![The full result image](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/hidden-in-almost-plain-sight/images/output-small.png)

The previously hidden space contains the flag:

    X-MAS{who_knows_wh3re_s4anta_hid3s_the_g1fts}

----

Note that the images in this writeup are resized to save some space, you can obtain the originals by manually following the steps presented here.
