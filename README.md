# Radio

Big task for Computer Networks 2020 at MIMUW University of Warsaw.

### Build

```
git clone
mkdir release && cd release
cmake .. && make
```

And to make documentation:

```
make doc
```

### Program description

Project contains two programs: radio-proxy, radio-client <br>
Radio proxy downloads audio and if requested metadata. In normal mode, writes received audio to stdout and metadata to stderr.
In proxy mode, received data are transferred to all conected clients. <br><br>
Usage is: <br><b>
./radio-proxy -h radio-server-name -r resource-to-download -p port-to-connect> [-m yes|no metadata] [-t server-timeout] [-P proxy-port] [-B multicast/broadcast-address] [-T client-timeout] <br><br></b>

Radio client is controlled by telnet connection. On telnet request, radio-client finds available proxy, finishes work, connects to proxy and downloads data. <br>
Received audio is written to stdout, metadata are sent to telnet and presented in telnet menu. <br><br>
Usage is: <br><b>
./radio-client -H proxy/multicast/broadcast-address -P proxy-port -p telnet-port [-T proxy-timeout] <br><br></b>

Detailed usage and communication protoc is available in todo.