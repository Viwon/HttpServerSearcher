using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Linq;
using CommandLine;

namespace HttpServerSearcher {
    class Program {

        // Define a class to receive parsed values
        class Options {
            [Option('v', "verbose", HelpText = "Verbose operation.")]
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

        static bool Verbose;

        static void Main(string[] args) {
            //var a = "-v".Split();
            Options settings = null;
            var parse = Parser.Default.ParseArguments<Options>(args)
                .WithParsed<Options>(options => { settings = options;}
            );
            if(parse is NotParsed<Options>) {
                return;
            }
            Verbose = settings.Verbose;

            List<IPAddress> addresses = GetIPAddresses();
            var totalIPs = addresses.Count;
            if(totalIPs == 0) {
                Console.WriteLine("No polling addresses found.");
                return;
            }
            addresses = IcmpCheck(addresses, settings.Timeout);
            var serverList = HttpCheck(addresses, settings.Timeout);
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

        public static List<IPAddress> IcmpCheck(List<IPAddress> addresses, int timeout = 100) {
            //if(addresses == null) throw new ArgumentNullException(nameof(addresses));
            //if(timeout < 0) throw new ArgumentOutOfRangeException("timeout is less than 0.");
            List<IPAddress> replied = new List<IPAddress>();
            CountdownEvent cde = new CountdownEvent(addresses.Count);;
            object addressesLock = new object();
            WriteLine("{0} addresses will be polled...", addresses.Count);
            foreach(IPAddress address in addresses) {
                Ping ping = new Ping();
                ping.PingCompleted += (sender, e) => {
                    if(e.Cancelled) {
                        WriteLine("{0} ping canceled.", e.UserState);
                    } else if(e.Error != null) {
                        WriteLine("{0} ping error: {1}", e.UserState, e.Error.ToString());
                    } else if(e.Reply.Status == IPStatus.Success) {
                        WriteLine("{0} ping time is {1} ms", e.Reply.Address, e.Reply.RoundtripTime);
                        lock(addressesLock) {
                            replied.Add(e.Reply.Address);
                        }
                    } else if(e.Reply.Status != IPStatus.TimedOut) {
                         WriteLine("{0} ping failed: {1}", e.UserState, e.Reply.Status);
                    }
                    // Let the main thread resume.
                    cde.Signal();
                };
                ping.SendAsync(address, timeout, address);
            }
            // And wait for queue to empty by waiting on cde
            cde.Wait(); // will return when cde count reaches 0
            // It's good to release a CountdownEvent when you're done with it.
            //cde.Dispose();
            WriteLine();
            return replied;
        }

        public static Dictionary<string, string> HttpCheck(List<IPAddress> addresses, int timeout = 100) {
            Dictionary<string, string> serverList = new Dictionary<string, string>();
            string url;
            WriteLine("{0} addresses addresses will be checked on HTTP...", addresses.Count);
            foreach (IPAddress address in addresses) {
                url = "http://" + address.ToString();
                HttpWebRequest WebRequestObject = (HttpWebRequest)HttpWebRequest.Create(url);
                //WebRequestObject.Method = "HEAD";
                WebRequestObject.KeepAlive = false;
                WebRequestObject.Timeout = timeout;
                HttpWebResponse ResponseObject = null;
                try {
                    ResponseObject = (HttpWebResponse)WebRequestObject.GetResponse();
                } catch (WebException ex) {
                    WriteLine("{0} {1}", url, ex.Message);
                    continue;
                }
                WriteLine("{0} HTTP Server '{1}'", url, ResponseObject.Server);
                serverList.Add(address.ToString(), ResponseObject.Server);
                /*
                if(ResponseObject.Headers["Server"].StartsWith("binarflow", true, null)) {
                    serverAddresses.Add(address);
                    WriteLine("Detected Binarflow device '{0}', URL {1}", ResponseObject.Headers["Server"], url);
                    //continue;
                }
                */
                //    HeaderList.Add(HeaderKey, ResponseObject.Headers[HeaderKey]);
                ResponseObject.Close();
            }
            return serverList;
/*
            // And output them:
            foreach (string HeaderKey in Headers.Keys) 
                WriteLine("{0}: {1}", HeaderKey, Headers[HeaderKey]);
*/
         }

        static void WriteLine(string format = null, params object[] arg) {
            if(Verbose) {
                if(format != null) {
                    Console.WriteLine(format, arg);
                } else {
                    Console.WriteLine();
                }
            }
        }
    }
}
