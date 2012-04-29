CS3753 (Operating Systems)
Spring 2012
University of Colorado Boulder
Programming Assignment 5
A FUSE Encrypted File System
Public Code
By Alex Beal <http://usrsb.in>

###Build###
```
make
```

###Usage###
```
./pa5-encfs KEY MIRROR_DIR MOUNT_POINT
```

###Notes###
If you edit an unencrypted file through the mountpoint with a program like Vim, the file will be encrypted. This is a quirk of how Vim uses swap files.

###Credits###
By Andy Sayler - 2012
<www.andysayler.com>

Inspired by work from Chris Wailes - 2010
<chris.wailes@gmail.com>

With help from:
Junho Ahn - 2012

Please see README.old for more info
