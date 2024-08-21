# WebListener
Windows C++ program to Listen the HTTP/HTTPS traffic.
Firefox was recommanded to set proxy as 127.0.0.1 on port 8080 to listen
![image](https://github.com/user-attachments/assets/f485ab83-5dcd-4462-84e3-de76283bff80)
![image](https://github.com/user-attachments/assets/4700ddb8-80e5-479e-a6ba-d2b5e407aab2)

<code>git clone https://github.com/Microsoft/vcpkg.git</code>

<code>cd vcpkg</code>

<code>./vcpkg integrate install</code>

<code>./bootstrap-vcpkg.bat</code>

<code>./vcpkg install zlib</code>

<code>./vcpkg install boost-iostreams</code>

<code>./vcpkg install boost-system boost-thread</code>

<code>./vcpkg install openssl:x64-windows</code>

<code>./vcpkg install boost</code>

<code>./vcpkg install boost-beast</code>

You also need to add the

<code>path_to_your_vcpkg\installed\x64-windows\include</code>

<code>path_to_your_vcpkg\installed\x64-windows\lib</code>

to your IDE dependency

For example, my path is
<code>E:\vcpkg-master\installed\x64-windows\include</code>
<code>E:\vcpkg-master\installed\x64-windows\lib</code>
