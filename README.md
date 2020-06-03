# HTTP server searcher
An application that searches for HTTP servers. Useful for finding the IP address of devices with web-interface, such as routers, printers, etc., when their IP address is unknown or forgotten.

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
HttpServerSearcher [<ADDRESSES>] [-t <TIMEOUT>] [-v]
```
where
* -t - specifies ICMP/HTTP requests timeout, at millisecond (Default: 100).
* -v - specifies operate in verbose mode.
* <ADDRESSES> - specifies the IP addresses to scan, the following formats are available:
  - X.X.X.X - single IP address, X.X.X.X
  - X.X.X.X-Y.Y.Y.Y - IP address range, from X.X.X.X to Y.Y.Y.Y, inclusive
  - X.X.X.X+YYYYY - series of IP addresses, X.X.X.X IP address, and another Y IP addresses following it
  - X.X.X.X/YY - all IP addresses of a subnet that includes an X.X.X.X address and has a YY prefix
  - if <ADDRESSES> is omitted, all addresses of available local networks will be scanned 

### Example
```sh
HttpServerSearcher 172.16.0.1 172.16.1.10-172.16.1.30 172.16.0.70+9 172.16.19.0/24
```
the following addresses will be scanned: 172.16.0.1, 172.16.1.10-172.16.1.30, 172.16.0.70-172.16.0.79, 172.16.19.1-172.16.19.254

## How it works
 1. If the user specified IP addresses on the command line, go to step 5
 2. Gets the network interfaces in the system
 3. Gets the IP addresses of the machine on Ethernet networks.
 4. By IP address and prefix (mask) is receives a range of IP addresses (IPv4 only) for scanning
 5. Pings (sends an ICMP request) IP addresses, leaves only the addresses from which the response was received
 6. Sends an HTTP “GET” request to the remaining addresses. Hosts from which the response was received, there are devices of interest to us
 7. Displays the IP addresses of devices and the contents of the HTTP "Server" header of their response

## Roadmap
* Filter HTTP servers by header content (this version displays servers whose response has the HTTP header "Server", content no metter)
* Support IPv6(maybe)

[.NET Core]: https://dotnet.microsoft.com/download
