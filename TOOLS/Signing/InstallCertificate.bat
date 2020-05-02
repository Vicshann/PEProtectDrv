set CERT_NAME="Vicshann(Test Certificate)"
set CERT_ROOT=root 
set CERT_PUBL=trustedpublisher 
set CERT_STOR="PrivateCertStore"   

echo on
echo "%~dp0"
cd
"%~dp0\Bin\certmgr.exe" /del /r LocalMachine /s %CERT_PUBL% /c /n %CERT_NAME%
"%~dp0\Bin\certmgr.exe" /del /r LocalMachine /s %CERT_ROOT% /c /n %CERT_NAME%
"%~dp0\Bin\makecert.exe" -$ individual -r -pe -ss %CERT_STOR% -n  CN=%CERT_NAME% %CERT_NAME%.cer
"%~dp0\Bin\certmgr.exe" /add %CERT_NAME%.cer /s /r localMachine %CERT_ROOT%
"%~dp0\Bin\certmgr.exe" /add %CERT_NAME%.cer /s /r localMachine %CERT_PUBL%