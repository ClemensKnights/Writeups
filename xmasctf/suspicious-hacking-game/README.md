We were presented with a PNG image (too big to upload it here, sorry) that contains a "real" image in the upper area and then some seemingly random data in the last 1307 lines.

So we opened it with GIMP, extracted that rectangle (we'll call it footer) and tried to analyze it. Didn't really make sense yet, so we looked for another clue.

Then we saw that the rectangle looked basically like the following:

```
________XXXXX
_____________
_____________
```

where `X` is a 0xfefefe pixel. So what if this is some kind of padding? Then the data should start with it, not have it's first line separated from the rest by this.

Flipping the image horizontally:

```
XXXXX________
_____________
_____________
```

It looked a lot better.

```
$ strings -n15 flipped.png

...
lld.bilrocsm/deganaM/ataD/nib/stessa
...
```

Looks just like a reversed string, so let's reverse the image byte by byte:

```
xxd -p -c1 footer_flip_horizontal_strip.data | tac | xxd -p -r > footer_flip_horizontal_strip_reverse.data
```

This is a valid 7z archive now, containing an APK.

The APK is an android game where you have to click 50000 times for each character of the flag.

The easiest way now would be to decompile it, and run strings on everything we can find. This would actually have worked. But we weren't that smart. Instead we used an Emulator and MonkeyRunner (from the android-sdk) to simulate taps.

```
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
device = MonkeyRunner.waitForConnection()
for i in range(1, 1000000):
    device.touch(500, 500, 'DOWN_AND_UP')
```

Took us 10 hours (over night), but then we got the flag: `X-MAS{S4v3_Th1s_1m4g3_4nd_g3t_4_fr33_g4m3}`
