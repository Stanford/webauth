@echo off

echo Copying windows\config.h to config.h 
copy windows\config.h config.h

echo Copying src\libwebauth\webauth.h.in to src\libwebauth\webauth.h
copy src\libwebauth\webauth.h.in src\libwebauth\webauth.h

echo Copying windows\buildenv.bat to buildenv.bat
copy windows\buildenv.bat buildenv.bat

echo Now edit buildenv.bat, then type:
echo     nmake /f Makefile.vc debug
echo or: nmake /f Makefile.vc release

