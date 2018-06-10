call prep.bat

if exist build32 (
    cd build32
    msbuild /t:Clean,Build /p:Configuration=Release probe-dll-export.sln
    if exist Release\probe-dll-export.exe copy Release\probe-dll-export.exe ..\probe-dll-export-32.exe
    cd ..
)

if exist build64 (
    cd build64
    msbuild /t:Clean,Build /p:Configuration=Release probe-dll-export.sln
    if exist Release\probe-dll-export.exe copy Release\probe-dll-export.exe ..\probe-dll-export-64.exe
    cd ..
)
