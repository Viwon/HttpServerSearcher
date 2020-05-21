# HTTP server searcher
An application that searches for active HTTP servers. Useful for finding the IP address of devices with web-interface, such as routers, printers, etc., when their IP address is unknown or forgotten.

## How to build
 1. Download and install [.NET Core]
 2. Download or clone [this](https://github.com/Viwon/HttpServerSearcher) repository
 3. Open the repository directory on the command line
 4. Run the command

```sh
dotnet publish -r <RID> -c Release /p:PublishSingleFile=true /p:PublishTrimmed=true -o <OUTPUT_DIRECTORY>
```
where 
* \<RID\> - specifies the target platform, sample ```linux-x64``` or ```win-x64``` (see [here](https://docs.microsoft.com/dotnet/core/rid-catalog) for details)
* \<OUTPUT_DIRECTORY\> - specifies the path for the output directory

 5. Get the app in \<OUTPUT_DIRECTORY\>

## Usage
```sh
HttpServerSearcher
```
## How it works
 1. Gets the network interfaces in the system
 2. Gets the host IP addresses on Ethernet networks
 3. By IP address and prefix (mask) is receives a range of IP addresses (IPv4 only) for scanning
 4. Pings (sends an ICMP request) IP addresses, leaves only the addresses from which the response was received
 5. Sends an HTTP “GET” request to the remaining addresses. Hosts from which the response was received, there are devices of interest to us
 7. Displays the IP addresses of devices and the contents of the HTTP "Server" header of their response

## Roadmap
* Passing arguments from the command line (this version not accept command line arguments)
* Silent operation. Only the IP addresses of the found servers and the contents of their headers are output(this version verbose)
* Scan user-specified IP addresses (this version scan all available local networks)
* User-specified ICMP/HTTP request timeout (in this version 100/100000 millisecond)
* Filter HTTP servers by header content (this version displays servers whose response has the HTTP header "Server", content no metter)
* Support IPv6(maybe)

> Sorry for my bad English

[.NET Core]: https://dotnet.microsoft.com/download
