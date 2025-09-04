Follow this guide to flash LineageOS 16, Magisk and Kali NetHunter: https://xdaforums.com/t/guide-herolte-installing-kali-nethunter-on-samsung-s7-los-16.4757800/


Build this module and add to Magisk.

Use as:

adb root && adb shell

/data/local/tmp/eapol_capture.sh -c 6 -w /sdcard/eapol_capture

/data/local/tmp/eapol_capture.sh --hop -w /sdcard/eapol_capture

/data/local/tmp/eapol_capture.sh -c 36 -b 00:11:22:33:44:55 -w /sdcard/eapol_capture

