#! /bin/sh
$EXTRACTRC *.ui >> rc.cpp
$XGETTEXT *.cpp -o $podir/ksshaskpass.pot
rm -f rc.cpp
