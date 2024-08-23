@echo off

cd source/
if not exist _modules mkdir _modules

cd _modules/

if exist *.rst del *.rst /Q

cd ../../

:: Generate the API documentation
sphinx-apidoc -o source/_modules -e -M -f ../brski-py

:: Run make.bat in a new command window and continue immediately
start "" cmd /c "make.bat html"

:: Add a delay to give Sphinx some time to generate the files, if needed
timeout /t 5 /nobreak > nul

:: Open the HTML file
start build/html/index.html
