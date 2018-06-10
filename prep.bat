if exist build32 rd /s /q build32
if not exist build32 md build32
cd build32
cmake -G "Visual Studio 15 2017" --build=. ..
cd ..

if exist build64 rd /s /q build64
if not exist build64 md build64
cd build64
cmake -G "Visual Studio 15 2017 Win64" --build=. ..
cd ..
