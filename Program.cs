using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Linq;// .ToList()
using System.Text.RegularExpressions;
using CommandLine;

namespace HttpServerSearcher {

    class Program {

        const int ThreadsLimit = 50;
        public static bool IsVerbose = false;
        public static int Timeout = 100;

        // Define a class to receive parsed values
        class Options {
            [Option('v', "verbose", Default = false, HelpText = "Verbose operation.")]
            public bool Verbose { get; set; }

            [Option('t', "timeout", Default = 100, HelpText = "ICMP/HTTP request timeout, millisecond.")]
            public int Timeout { get; set; }
/*
            [Option('s', "server", Default = "*", HelpText = "HTTP server header for search.")]
            public string Server { get; set; }
*/
            [Value(0, MetaName = "Addresses", HelpText = "IP addresses for scan.")]
            public IEnumerable<string> Addresses { get; set;}

        }

        static void Main(string[] args) {
            Options settings = null;
            List<IPAddress> addresses = null;
            var parse = Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options => { settings = options;}
            );
            if(parse is NotParsed<Options>) {
                return;
            }
            
            IsVerbose = settings.Verbose;
            Timeout = settings.Timeout;
            if(settings.Addresses.Count() != 0) {
                addresses = StringsToIp4List(settings.Addresses);
                if(addresses == null) {
                    Console.WriteLine("Addresses parsing error.");
                    return;
                }
            } else {
                addresses = GetIPAddresses();
            }

            var totalIPs = addresses.Count;
            if(totalIPs == 0) {
                Console.WriteLine("No polling addresses found.");
                return;
            }
            addresses = IcmpCheck(addresses);
            var serverList = HttpCheck(addresses);
            Console.WriteLine("{0} IP addresses were polled/ {1} replied to the ICMP-request/ {2} responded to the HTTP-request.", totalIPs, addresses.Count, serverList.Count);
            foreach(KeyValuePair<string, string> server in serverList) {
                Console.WriteLine("http://{0}: {1}", server.Key, server.Value);
            }
        }

        public static List<IPAddress> GetIPAddresses() {
            List<IPAddress> scanAddresses = new List<IPAddress>();
            IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            WriteLine("Interface information for {0}.{1}     ",
                    computerProperties.HostName, computerProperties.DomainName);
            if (nics == null || nics.Length < 1) {
                WriteLine("  No network interfaces found.");
                return scanAddresses;
            }

            WriteLine("  Number of interfaces .................... : {0}", nics.Length);
            foreach (NetworkInterface adapter in nics) {
                IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                WriteLine();
                WriteLine(adapter.Description);
                WriteLine(String.Empty.PadLeft(adapter.Description.Length,'='));
                WriteLine("  Interface type .......................... : {0}", adapter.NetworkInterfaceType);
                string mac = "";
                byte[] bytes = adapter.GetPhysicalAddress().GetAddressBytes();
                for(int i = 0; i< bytes.Length; i++) {
                    if(i != 0)
                        mac += '-';
                    mac += bytes[i].ToString("X2");
                }
                WriteLine("  Physical Address ........................ : {0}", mac);
                WriteLine("  Operational status ...................... : {0}", adapter.OperationalStatus);
                if(adapter.NetworkInterfaceType != NetworkInterfaceType.Ethernet || (!adapter.Supports(NetworkInterfaceComponent.IPv4) && !adapter.Supports(NetworkInterfaceComponent.IPv6))) {
                    WriteLine("  (Skipped)");
                    continue;
                }
                
                // Create a display string for gateways
                string gateways = "";
                foreach( GatewayIPAddressInformation gipi in adapterProperties.GatewayAddresses ) {
    				gateways += gipi.Address + " ";
    			}
                WriteLine("  Gateways ................................ : {0}", gateways);

                foreach (UnicastIPAddressInformation uipi in adapterProperties.UnicastAddresses) {
                    int prefixLength = 0;
                    try {
                        prefixLength = uipi.PrefixLength;
                    } catch(PlatformNotSupportedException) {
                        prefixLength = -1;
                    }
                    if(uipi.Address.AddressFamily == AddressFamily.InterNetwork) {
                        // Если не удалось получить длину префикса, вычисляем ее по маске
                        if(prefixLength < 0) {
                            Byte[] maskBytes = uipi.IPv4Mask.GetAddressBytes();
                            // При необходимости, переводим BigEndian порядок следования байт маски сети, в LittleEndian
                            if(BitConverter.IsLittleEndian) {
                                Array.Reverse(maskBytes);
                            }
                            UInt32 mask = BitConverter.ToUInt32(maskBytes, 0);
                            for(prefixLength = 0; (mask != 0) && (prefixLength < 32); ++prefixLength) {
                                mask = mask << 1;
                            }
                        }
                        WriteLine("  Unicast IPv4 Address .................... : {0}/{1}", uipi.Address, prefixLength);
                        //WriteLine("     Subnet mask .......................... : {0}", uipi.IPv4Mask);
                        //WriteLine("     Prefix Length ........................ : {0}", uipi.PrefixLength);
                        
                        UInt32 hostAddress = (UInt32)Ip4ToInt32(uipi.Address);
                        UInt32 netMask = (UInt32)Ip4ToInt32(uipi.IPv4Mask);
                        UInt32 begAddress = hostAddress & netMask;// networkAddress
                        UInt32 endAddress = begAddress ^ ~netMask;// broadcastAddress
                        // Skip network and broadcast addresses
                        if(!uipi.IPv4Mask.Equals(IPAddress.Parse("255.255.255.255")) && !uipi.IPv4Mask.Equals(IPAddress.Parse("255.255.255.254"))) {
                            begAddress++;
                            endAddress--;
                        }
                        for (var address = begAddress; address <= endAddress; address++) {
                            scanAddresses.Add(Int32ToIp4((Int32)address));
                        }
                    } else if (uipi.Address.AddressFamily == AddressFamily.InterNetworkV6) {
                        if(prefixLength < 0) {
                            WriteLine("  Unicast IPv6 Address (Skipped) .......... : {0}/(Undefined)", uipi.Address);
                            continue;// Пропускаем т.к. неизвсен префикс сети
                        }
                        WriteLine("  Unicast IPv6 Address (Skipped) .......... : {0}/{1}", uipi.Address, prefixLength);
                        continue;// Пропускаем т.к. пока не ясно что делать с IPv6
                        //ipRange = new IPRange();
                    } else {
                        continue;
                    }
                    //subnetRanges.Add(ipRange);
                }
            }
            WriteLine();
            return scanAddresses.Distinct().ToList();
        }

        public static List<IPAddress> GetIPAddresses(string strAddresses) {
            List<IPAddress> listAddresses = new List<IPAddress>();
            return listAddresses;
        }

        public static List<IPAddress> IcmpCheck(List<IPAddress> addresses) {
            //if(addresses == null) throw new ArgumentNullException(nameof(addresses));
            //if(timeout < 0) throw new ArgumentOutOfRangeException("timeout is less than 0.");
            List<IPAddress> replied = new List<IPAddress>();
            object repliedLock = new object();
            int remainingAddresses = addresses.Count;
            WriteLine("{0} addresses will be polled...", addresses.Count);
            Semaphore pool = new Semaphore(ThreadsLimit, ThreadsLimit);
            foreach(IPAddress address in addresses) {
                pool.WaitOne();
                Ping ping = new Ping();
                ping.PingCompleted += (sender, e) => {
                    bool success = false;
                    if(e.Cancelled) {
                        WriteLine("{0} ping canceled.", e.UserState);
                    } else if(e.Error != null) {
                        WriteLine("{0} ping error: {1}", e.UserState, e.Error.ToString());
                    } else if(e.Reply.Status == IPStatus.Success) {
                        WriteLine("{0} ping time is {1} ms", e.Reply.Address, e.Reply.RoundtripTime);
                        success = true;
                    } else if(e.Reply.Status != IPStatus.TimedOut) {
                         WriteLine("{0} ping failed: {1}", e.UserState, e.Reply.Status);
                    }
                    lock(repliedLock) {
                        remainingAddresses--;
                        if(success) replied.Add(e.Reply.Address);
                    }
                    // Let the main thread resume.
                    pool.Release();
                };
                ping.SendAsync(address, Timeout, address);
            }
            bool waitRemaining;
            do {
                pool.WaitOne();
                lock(repliedLock) {
                    waitRemaining = (remainingAddresses != 0);
                }
            } while(waitRemaining);
            pool.Dispose();
            WriteLine();
            return replied;
        }

        public static Dictionary<string, string> HttpCheck(List<IPAddress> addresses) {
            Dictionary<string, string> serverList = new Dictionary<string, string>();
            WriteLine("{0} addresses will be checked on HTTP...", addresses.Count);
            HTTPHeaders httpHeaders = new HTTPHeaders(Timeout);
            foreach (IPAddress address in addresses) {
                WriteLine($"{address}:");
                if(httpHeaders.Request(address.ToString())){
                    WriteLine($"  {httpHeaders.StartLine}");
                    if(IsVerbose) {
                        foreach(KeyValuePair<string, string> header in httpHeaders.Headers) {
                            Console.WriteLine("  {0}: {1}", header.Key, header.Value);
                        }
                    }
                    string server;
                    if(httpHeaders.Headers.TryGetValue("Server", out server)) {
                        serverList.Add(address.ToString(), server);
                    }
                } else {
                     WriteLine($"  {httpHeaders.Error}");
                }
            }
            WriteLine();
            return serverList;
        }

        public static List<IPAddress> StringsToIp4List(in IEnumerable<string> ipStrings) {
            List<IPAddress> addresses = new List<IPAddress>();
            Regex ipRegex = new Regex(@"^(?<base>(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(?:(?(-)-(?<end>(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))|(?(\+)\+(?<amount>\d{1,5})|(?(/)/(?<prefix>(?:3[0-2]|[1-2]?\d))|))))?$");

            foreach(string ipString in ipStrings) {
                Match match = ipRegex.Match(ipString);
                if(!match.Success) {
                    WriteLine("Option '{0}' is defined with a bad format.", ipString);
                    return null;
                }
                UInt32 begAddress = (UInt32)Ip4ToInt32(IPAddress.Parse(match.Groups["base"].Value));
                UInt32 endAddress = begAddress;
                if(match.Groups["end"].Success) {
                    endAddress = (UInt32)(UInt32)Ip4ToInt32(IPAddress.Parse(match.Groups["end"].Value));
                } else if(match.Groups["prefix"].Success) {
                    UInt32 prefix = UInt32.Parse(match.Groups["prefix"].Value);
                    UInt32 shift = 32 - prefix;
                    UInt32 netMask = UInt32.MaxValue;
                    // Make network mask from prefix
                    for(var i = 0; i < shift; i++) {
                        netMask = netMask << 1;
                    }
                    begAddress = begAddress & netMask;// Network address
                    endAddress = begAddress ^ ~netMask;// Broadcast address
                    // Exclude the network and broadcast addresses from the scan list for networks with a prefix other than 31/32
                    if(!(prefix == 31 || prefix == 32)) {
                        begAddress++;
                        endAddress--;
                    }
                } else if(match.Groups["amount"].Success) {
                    endAddress = begAddress + UInt32.Parse(match.Groups["amount"].Value);
                }

                for(var address = begAddress; address <= endAddress; address++) {
                    addresses.Add(Int32ToIp4((Int32)address));
                }
            }
            return addresses.Distinct().ToList();
        }

        public static Int32 Ip4ToInt32(in IPAddress ipAddress) {
            return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0));
        }

        public static IPAddress Int32ToIp4(in Int32 intAddress) {
            return new IPAddress(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(intAddress)));
        }
        
        static void WriteLine(string format = null, params object[] arg) {
            if(IsVerbose) {
                if(format != null) {
                    Console.WriteLine(format, arg);
                } else {
                    Console.WriteLine();
                }
            }
        }
    }

    class HTTPHeaders {
        
        const int BufferSize = 256;
        const int MaxFieldSize = 1024;
        private int _timeout;
        private byte[] _recievedBytes;
        private byte[] _headerBytes;
        private string _error;
        private string _address;
        private string _startLine;
        private Dictionary<string, string> _headers;

        public Dictionary<string, string> Headers { get => _headers; }
        public string Address { get => _address; }
        public string StartLine { get => _startLine; }
        public string Error { get => _error; }

        public HTTPHeaders(int Timeout = 100) {
            _timeout = Timeout;
            _recievedBytes = new byte[BufferSize];
            _headerBytes = new byte[BufferSize];
        }

        public bool Request(string ipString) {
            IPAddress address;
            if(!IPAddress.TryParse(ipString, out address))
                throw new ArgumentOutOfRangeException(nameof(ipString));
            _address = address.ToString();
            _error = null;
            _startLine = null;
            _headers = null;
            string request = String.Format("{0} / HTTP/1.1\r\nHost: {1}\r\nConnection: close\r\n\r\n", "GET", _address);
            Socket socket = null;
            bool endOfHeaders = false;// Message header has received
            bool wsFlag = false;//  Current byte is White Space
            bool crFlag = false;// Current byte is Carriage Return
            bool lfFlag = false;// Current byte is LineFeed
            bool ctlFlag = false;// Current byte is control character
            bool prevLfFlag = false;// Previous byte is LineFeed
            int colonPos = -1;// Position of the colon in the field
            int headerLen = 0;
            try {
                // Connect to host
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.SendTimeout = _timeout;
                socket.ReceiveTimeout = _timeout;
                IAsyncResult result = socket.BeginConnect(address, 80, null, null);
                if(result.AsyncWaitHandle.WaitOne(_timeout, true)) {
                    socket.EndConnect(result);
                }
                result.AsyncWaitHandle.Dispose();
                if(!socket.Connected) {
                    throw new SocketException((int)SocketError.TimedOut);
                }
                // Send request
                socket.Send(System.Text.Encoding.ASCII.GetBytes(request));
                // Get response
                do {
                    int total = socket.Receive(_recievedBytes);
                    for(int i = 0; i < total; i++) {
                        wsFlag = _recievedBytes[i] == ' ' || _recievedBytes[i] == '\t';
                        crFlag = _recievedBytes[i] == '\r';
                        lfFlag = _recievedBytes[i] == '\n';
                        ctlFlag = (_recievedBytes[i] >= 0 && _recievedBytes[i] <= 31) || _recievedBytes[i] == 127;
                        if(ctlFlag && !(crFlag || lfFlag)) {// Response message contain a control character
                            _error = "ServerProtocolViolation";
                            break;
                        }
                        // If the line starts with a space, this is a multi-line header, skip to the true end
                        if(prevLfFlag && !wsFlag) {
                            if(headerLen == 0) {
                                endOfHeaders = true;
                                break;
                            }
                            string line = System.Text.Encoding.ASCII.GetString(_headerBytes, 0, headerLen);
//                            WriteLine($"  {line}");
                            if(_startLine == null) {
                                _startLine = line;
                                Match match = Regex.Match(_startLine, @"\AHTTP/\d+\.\d+ \d{3} [^\x00-\x1F\x7F]*\Z", RegexOptions.IgnoreCase);
                                if(!match.Success) {// Response start line has an invalid format
                                    _error = "ServerProtocolViolation";
                                    break;
                                }
                            } else {
                                //int colonPos = line.IndexOf(':');
                                if(colonPos == -1) {// The header field does not contain a colon
                                    _error = "ServerProtocolViolation";
                                    break;
                                } else {
                                    if(_headers == null) {
                                        _headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                                    }
                                    string name = line.Substring(0, colonPos).Trim();
                                    string value = line.Substring(colonPos + 1).Trim();
                                    
                                    if(_headers.ContainsKey(name)) {// multiple header
                                        _headers[name] += "," + value;
                                    } else {
                                        _headers.Add(name, value);
                                    }
                                }
                            }
                            colonPos = -1;
                            headerLen = 0;
                        }
                        if(!ctlFlag) {
                            if(_recievedBytes[i] == ':' && colonPos == -1) {
                                colonPos = headerLen;
                            }
                            _headerBytes[headerLen++] = _recievedBytes[i];
                        }
                        if(headerLen == MaxFieldSize) {// The header field is larger than the maximum buffer size
                            _error = "MessageLengthLimitExceeded";
                        }
                        if(headerLen >= _headerBytes.Count()) {
                            Array.Resize(ref _headerBytes, _headerBytes.Count() + BufferSize);
                        }
                        prevLfFlag = lfFlag;
                    }
                } while(!endOfHeaders && _error == null);
            } catch(SocketException ex) {
                if(headerLen != 0) {// Receive time out, the end of the headers is not reached
                    _error = "ReceiveFailure";
                } else {
                    _error = ex.SocketErrorCode.ToString();//ex.Message;
                }
            } finally {
                socket?.Dispose();
            }
            return _error == null;
        }
    }
}
