After flashing LOS 16 and Magisk, add Kali NetHunter as Magisk Module.
Build this module and add to Magisk.

Use as:

adb root && adb shell

/data/local/tmp/eapol_capture.sh -c 6 -w /sdcard/eapol_capture

/data/local/tmp/eapol_capture.sh --hop -w /sdcard/eapol_capture

/data/local/tmp/eapol_capture.sh -c 36 -b 00:11:22:33:44:55 -w /sdcard/eapol_capture

