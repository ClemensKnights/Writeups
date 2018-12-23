# Mission: Save the Christmas
### X-MAS CTF 2018, Misc / Forensics [487]

> Santa's reindeers have been kidnapped! John Athan, Santa's right hand, has been watching you for a while and needs your help. Your mission, should you choose to accept it, is to help John Athan save Christmas.

This is a multi-stage challenge.

#### Stage 1: A Riddle

When connecting to the server, you are presented with a riddle:

    Hello! My name is John Athan. I am Santa's right hand. Unfortunately, the Christmas is in danger. The reindeers have been trapped behind a door that requires some sort of username, password combination. Your mission, should you choose to accept it, is to help me solve some tasks and save the Christmas. If successful, you will be rewarded with a lovely flag.
    
     You have 3 lives. Good luck!
    
    If you want me you'll have to share me but if you share me I will be gone. What am I?(one word)

Google helps find the solution: `secret`. This advances you to the next stage.

#### Stage 2: A weird hash function

    Congrats! Moving to the next task...
    
    While you were struggling with that riddle I managed to extract some hashes, but triggered an alarm. I don't know much about them. They are 14 characters long and all of them contain the word 'stealer' and 7 digits. All the digits are placed after the word or before the word. The hash for the word 'admin' is -5290733415256081176
    You only have 60 seconds. I'm validating the strings as you send them so any mistake is fatal. Send the usernames, one per line. Here's an example:
    Anyway here are the hashes:
(followed by ten hash values)

The most difficult part of this stage is to actually identify the hash function. After trying just about every hash (cryptographic or otherwise) that we could think of, we eventually found this to be Python 2’s default `hash(...)` function:

    Python 2.7.13 (default, Jan 28 2017, 23:07:36)
    [GCC 6.3.1 20170109] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> hash('admin')
    -5290733415256081176

With the instructions given by the challenge, we can pre-generate all of the possible hashes by recreating the hash function. Unfortunately, the inner workings are not really documented officially, but we can find them in Python’s [source code](https://svn.python.org/projects/python/trunk/Objects/stringobject.c).

The `generate-table.cc` program works its way through the hashes in a couple of seconds - just give it a directory to dump output files into. From Python, we later use `grep` to quickly sift through these files to recover the input passwords (the `client.py` script will automatically compile and run the generator program if the hashes have not been generated yet).

Sending the correct plaintext for each of the hashes advances us to the next stage.

#### Stage 3: Reindeers

    Congrats! Moving to the next task...
    
    Ok... I feel we're getting closer. I now need you to tell me how many reindeers are in this image.
     https://pasteboard.co/HRfn1ys.jpg
    You should send me (no_of_reindeers * (666 013)^3)  %  8240418671255430

The image is an ostensibly corrupt JPEG image. We can restore the image using ImageMagick:

    $ convert HRfn1ys.jpg stage_3_fixed.jpg
    convert: Corrupt JPEG data: 19 extraneous bytes before marker 0x6b `HRfn1ys.jpg' @ warning/jpeg.c/JPEGWarningHandler/389.
    convert: Unsupported marker type 0x6b `HRfn1ys.jpg' @ warning/jpeg.c/JPEGErrorHandler/330.

![The restored image of stage 3](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/mission-save-the-christmas/images/stage_3_fixed.jpg)

Of course, the two reindeers in the picture are not the only reindeers the challenge asks for.

    $ strings HRfn1ys.jpg | grep reindeer
    Copyright (c) 1998 Hidden reindeer Company
    red reindeer
    blue reindeer
    kiwi reindeer
    yellow reindeer.random reindeer. two reindeers.a small reindeer.a young reindeer.10 binary reindeers.funny reindeer.green reindeer.blue reindeer

This adds another fifteen reindeers to the count (note that the last line includes both "two reindeers" and "10 binary reindeers").

Computing `(17 * (666013 ** 3)) % m`, where `m` is the (variable) modulo from the message above sends us to the next stage.

#### Stage 4: Image forensics, part 1

    Congrats! Moving to the next task...
    
    Nicely done! You might actually have a shot at saving the Christmas. I have another image for you to analyze, but I'm a bit confused. I need a password so I can see where the reindeers are trapped at.
     https://pasteboard.co/HRwM0jU.png

We get another image, this time one that is actually valid.

![The image for stage 4](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/mission-save-the-christmas/images/HRwM0jU.png)

`exiftool` immediately hints at what is wrong (`Warning: [minor] Trailer data after PNG IEND chunk`), and `binwalk` tells us that the PNG image is actually also a ZIP file.

Unzipping gives us another image, `winter.jpg`:

![`winter.jpg`](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/mission-save-the-christmas/images/winter.jpg)

Again, there is a ZIP file attached to the image. After extracting, we get the `cat_final` file. `binwalk` is stumped, but your trusty hex editor allows you to see through the trickery:

    $ xxd cat_final | head
    00000000: 8947 4e50 0d0a 1a0a 0000 000d 5244 4849  .GNP........RDHI
    00000010: 0000 0280 0000 020c 0806 0000 0065 bf1d  .............e..
    00000020: 8000 001a f87a 5458 7452 6177 2070 726f  .....zTXtRaw pro
    00000030: 6669 6c65 2074 7970 6520 6578 6966 0000  file type exif..
    00000040: 78da ed9a 5996 1c37 9245 ffb1 8a5e 0266  x...Y..7.E...^.f
    00000050: c096 83f1 9cde 412f bfef 4304 4551 5255  ......A/..C.EQRU
    00000060: 770d 9fa5 1499 c9c8 0877 c086 3718 dc9d  w........w..7...
    00000070: fff9 efeb fe8b ff6a b5ea 7269 9def d5f3  .......j..ri....
    00000080: 5fb6 6c71 f043 f79f ff3e df83 cfef ef1f  _.lq.C...>......
    00000090: 2fc5 efab bfbc eefc fafe 22f2 52e2 7bfa  /.........".R.{.

We can see that this is yet another PNG file (e.g. through the `profile type exif` and `zTXt` markers), but with a corrupted header. Fixing the reversed magic bytes (`GNP` at the start to `PNG`) and header chunk name (`RDHI` to `IHDR`) gives us the password for the next stage, `sternocleidomastoidian`:

![`cat_final` after fixing](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/mission-save-the-christmas/images/cat_fixed.jpg)

#### Stage 5: Image forensics, part 2 (Merry Christmas)

    Congrats! Moving to the next task...
    
    We're finally here. Behind this door that you are unable to see are Santa's reindeers. Give me the password and we shall save the Christmas.
     https://pasteboard.co/HRyG0yE.png

![Image for stage 5](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/mission-save-the-christmas/images/HRyG0yE.png)

The image obtained for this challenge also has additional data behind the image data:

    $ strings HRyG0yE.png | tail -n1
    your password is red_herring

Of course (as one could have guessed from the password), this is actually a [red herring](https://en.wikipedia.org/wiki/Red_herring) - a distraction, not the actual password.

If we open the image in `stegsolve`, we find some data hidden in the least significant bits of each pixel. In BGR byte order, we obtain a suspicious-looking blob at the start of the image:

    00000000000000a1 566d704b4d465979  ........ VmpKMFYy
    52586c5457477856 59544a6f566c5977  RXlTWGxV YTJoVlYw
    5a473956566c6c33 566d7430616c5a73  ZG9VVll3 Vmt0alZs
    536c6857567a5650 5647786164475649  SlhWVzVP VGxadGVI
    614664534d326851 56315a6b53314e48  aFdSM2hQ V1ZkS1NH
    566b6468526c5a4f 566a4a6f4e6c5978  VkdhRlZO VjJoNlYx
    576d465862565a48 56473553546c5a75  WmFXbVZH VG5STlZu
    516c6857616b5a4c 56315a6b63316474  QlhWakZL V1Zkc1dt
    6446564e6245704a 56544a3063315979  dFVNbEpJ VTJ0c1Yy
    536c5a58626b7068 566a4e4351315273  SlZXbkph VjNCQ1Rs
    52546c5155543039 0affffffffffffff  RTlQUT09 ........

And indeed, after six layers of base64 encoding:

    $ echo VmpKMFYyRXlTWGxVYTJoVlYwZG9VVll3Vmt0alZsSlhWVzVPVGxadGVIaFdSM2hQV1ZkS1NHVkdhRlZOVjJoNlYxWmFXbVZHVG5STlZuQlhWakZLV1Zkc1dtdFVNbEpJVTJ0c1YySlZXbkphVjNCQ1RsRTlQUT09 > blob.txt
    $ base64 -d <(base64 -d <(base64 -d <(base64 -d <(base64 -d <(base64 -d < blob.txt)))))
    this_is_not_a_red_herring

This is the password that finally gets us the flag:

    You did it! You saved the Christmas! You may now go solve some more challenges. As promised, here is your flag:
    X-MAS{1_h4d_n0_id3a_th4t_you_c0uld_s4v3_th3_Chr1stm45}


