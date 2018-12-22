# BoJack Horseman's Sad Christmas

### X-MAS CTF 2018, Misc / Forensics [128]

> BoJack recieved a Christmas card from Diane but Princess Carolyn shredded it to bits. It looks like festive barf now! Can you help BoJack read the card?

For this challenge, you are only given one image:

![bojack.png](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/bojack-horsemans-sad-christmas/images/bojack.png)

The image contains only green and red pixels, and it becomes fairly obvious that this is some form of binary code.

Simply reinterpreting each red pixel as a `1` and each green pixel as a `0` leads to the desired result - a JPEG image containing the flag:

![The result image](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/bojack-horsemans-sad-christmas/images/extracted.jpg)

You can identify it as a JPEG file from the `JFIF` byte sequence as well as the magic number - both `binwalk` and the trusty old `file` utility would also do the job just fine.

The flag in the image is

    X-MAS{1_L0V3_B0J4ckH0rs3m4n}

