﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Linq;// .ToList()
using CommandLine;

namespace HttpServerSearcher {
    class Program {

        const int ThreadsLimit = 50;
        const int BufferSize = 256;
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

            [Value(0, MetaName = "Addresses", HelpText = "IP addresses for scan.")]
            public IEnumerable<string> Addresses { get; set;}
*/
        }

        static void Main(string[] args) {
            //var a = "-v".Split();
            Options settings = null;
            var parse = Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options => { settings = options;}
            );
            if(parse is NotParsed<Options>) {
                return;
            }

            IsVerbose = settings.Verbose;
            Timeout = settings.Timeout;

            List<IPAddress> addresses = GetIPAddresses();
            //List<IPAddress> addresses = new List<IPAddress>();
            //addresses.Add(IPAddress.Parse("172.16.0.1"));
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
                        
                        bytes = uipi.Address.GetAddressBytes();
                        UInt32 hostAddress = (UInt32)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(bytes, 0));
                        bytes = uipi.IPv4Mask.GetAddressBytes();
                        UInt32 netMask = (UInt32)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(bytes, 0));
                        UInt32 networkAddress = hostAddress & netMask;
                        UInt32 broadcastAddress = networkAddress ^ ~netMask;
                        // Перебераем все адреса подсети, кроме адреса самой сити и широковещательного
                        for (var address = networkAddress + 1; address < broadcastAddress; address++) {
                            var tmp  = IPAddress.HostToNetworkOrder((Int32)address);
                            bytes = BitConverter.GetBytes(tmp);
                            scanAddresses.Add(new IPAddress(bytes));
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
            string request;
            byte[] recievedBytes = new byte[BufferSize];
            byte[] headerBytes = new byte[BufferSize];
            IPEndPoint endPoint = new IPEndPoint(0, 80);
            WriteLine("{0} addresses addresses will be checked on HTTP...", addresses.Count);
            foreach (IPAddress address in addresses) {
                WriteLine($"{address}:");
                request = String.Format("{0} / HTTP/1.1\r\nHost: {1}\r\nConnection: close\r\n\r\n", "GET", address);
                endPoint.Address = address;
                Socket socket = null;
                string startLine = null;
                Dictionary<string, string> headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                try {
                    // Connect to host
                    socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    socket.Connect(endPoint);
                    socket.SendTimeout = Timeout;
                    socket.ReceiveTimeout = Timeout;
                    // Send request
                    socket.Send(System.Text.Encoding.ASCII.GetBytes(request));
                    // Get response
                    bool endOfHeaders = false;// Message header has received
                    bool wsFlag = false;//  Current byte is White Space
                    bool crFlag = false;// Current byte is Carriage Return
                    bool lfFlag = false;// Current byte is LineFeed
                    bool ctlFlag = false;// Current byte is control character
                    bool prevLfFlag = false;// Previous byte is LineFeed
                    int headerLen = 0;
                    do {
                        int total = socket.Receive(recievedBytes);
                        for(int i = 0; i < total; i++) {
                            wsFlag = recievedBytes[i] == ' ' || recievedBytes[i] == '\t';
                            crFlag = recievedBytes[i] == '\r';
                            lfFlag = recievedBytes[i] == '\n';
                            ctlFlag = (recievedBytes[i] >= 0 && recievedBytes[i] <= 31) || recievedBytes[i] == 127;
                            if(ctlFlag && !(crFlag || lfFlag)) {
                                //throw new WebException(null, null, WebExceptionStatus.ServerProtocolViolation, null);
                            }
                            // If the line starts with a space, this is a multi-line header, skip to the true end
                            if(prevLfFlag && !wsFlag) {
                                if(headerLen == 0) {
                                    endOfHeaders = true;
                                    break;
                                }
                                string line = System.Text.Encoding.ASCII.GetString(headerBytes, 0, headerLen);
                                WriteLine($"  {line}");
                                headerLen = 0;
                                if(startLine == null) {
                                    startLine = line;
                                } else {
                                    int colonPos = line.IndexOf(':');
                                    if(colonPos == -1) {
                                        //throw new WebException(null, null, WebExceptionStatus.ServerProtocolViolation, null);
                                    } else {
                                        string name = line.Substring(0, colonPos).Trim();
                                        string value = line.Substring(colonPos + 1).Trim();
                                        
                                        if(headers.ContainsKey(name)) {// multiple header
                                            headers[name] += "," + value;
                                        } else {
                                            headers.Add(name, value);
                                        }
                                    }
                                }
                            }
                            if(!ctlFlag) {
                                headerBytes[headerLen++] = recievedBytes[i];
                            }
                            if(headerLen >= headerBytes.Count()) {
                                Array.Resize(ref headerBytes, headerBytes.Count() + BufferSize);
                            }
                            prevLfFlag = lfFlag;
                        }
                    } while(!endOfHeaders);
                } catch (SocketException ex) {
                    WriteLine($"  {ex.SocketErrorCode}");//ex.Message);
                } finally {
                    socket?.Dispose();
                }
                string server;
                if(headers.TryGetValue("Server", out server)) {
                    serverList.Add(address.ToString(), server);
                }
            }
            WriteLine();
            return serverList;
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
}
