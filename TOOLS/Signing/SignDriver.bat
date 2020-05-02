set CERT_NAME="Vicshann(Test Certificate)"
set CERT_CROS=NONE
set CERT_STOR="PrivateCertStore" 
set FILE_NAME=%1 

echo on  
echo "%FILE_NAME%"
if exist "%~dp0%CERT_CROS%" goto :SetCross
set CROS_PATH=
goto :Execute
:SetCross
set CROS_PATH=/ac "%~dp0%CERT_CROS%"
echo "%CROS_PATH%"
:Execute
"%~dp0\Bin\signtool.exe" sign /v %CROS_PATH% /a /s %CERT_STOR% /n %CERT_NAME% "%FILE_NAME%"
"%~dp0\Bin\signtool.exe" verify /pa /v "%FILE_NAME%"
rem "%~dp0\Bin\signtool.exe" verify /kp /v "%FILE_NAME%"

set DIST_PATH=%~dp0..\..\DIST\
echo "%~dp0"
echo "%DIST_PATH%"
if not exist "%DIST_PATH%" goto :Exit
copy /Y /B "%FILE_NAME%" /B "%DIST_PATH%\"
:Exit

