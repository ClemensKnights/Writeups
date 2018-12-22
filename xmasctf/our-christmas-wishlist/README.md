# Our Christmas Wishlist

### X-MAS CTF 2018, Web [50]

> We have all gathered round to write down our wishes and desires for this Christmas! Please don't write anything mean, Santa will be reading this!

This challenge consists of a small 'wish list' web application that allows us to submit messages and displays them back to us.

![The web app](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/our-christmas-wishlist/images/app01.png)

![The web app after submitting a wish](https://raw.githubusercontent.com/ClemensKnights/Writeups/master/xmasctf/our-christmas-wishlist/images/app02.png)

The source code reveals the approach - injecting custom XML into the POST request and hoping that the sever is vulnerable to attacks involving external entities (XXE), which would allow us to read the flag file:

    var xml = "<message>" + document.getElementById("textarea").value + "</message>";

A textbook XXE attack is enough to retrieve the flag. This one uses the [`php://filter` stream](https://secure.php.net/manual/en/wrappers.php.php) to base64-encode our data just to make the output more resilient to special characters in some files:

    <!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file://{}">]><message>&xxe;</message>

During testing, the error messages reveal the location of the `index.php` file (`/var/www/html/`). We know that the `flag.txt` is in the same folder, and retrieve it using the finished exploit:

    X-MAS{_The_Ex73rnal_Ent1t13$_W4n7_To__Jo1n_7he_p4r7y__700______}

