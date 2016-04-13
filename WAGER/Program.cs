using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Numerics;

namespace WAGER
{
    public static class Log
    {
        public static void Debug(string msg)
        {
            Console.WriteLine(msg);
        }
    }

    static class Helpers
    {
        public static byte[] HexToByteArray(this string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }

    class LogonServer
    {
        

        TcpListener listener = new TcpListener(IPAddress.Any, 3724);
        List<WoWClient> clients = new List<WoWClient>();
        public IAccountProvider Provider;

        public LogonServer() { }

        public void HandleAuthPacket(AuthPacket packet, WoWClient sender)
        {
            Console.WriteLine("Handling {0}", packet.Type.ToString());
            if (packet.Type == PacketType.LogonChallenge)
                HandleLogonChallenge((ClientLogonChallengePacket)packet, sender);
            else if (packet.Type == PacketType.LogonProof)
                HandleLogonProof((ClientLogonProofPacket) packet, sender);

        }

        public void HandleLogonChallenge(ClientLogonChallengePacket packet, WoWClient sender)
        {
            Account account = Provider.FindAccount(packet.Identity);

            if (account == null)
            {
                // reply with Server Logon Challenge
                sender.Writer.Write((byte)0x0);     // cmd, always 0
                sender.Writer.Write((byte)0x0);     // instant dc?
                sender.Writer.Write((byte)AuthenticationResult.UnkAccount);
            }
            else if (account.Banned)
            {

                sender.Writer.Write((byte)0x0);     // cmd, always 0
                sender.Writer.Write((byte)0x0);     // instant dc?
                sender.Writer.Write((byte)AuthenticationResult.Banned);
            }
            else if(packet.Build != 5875) // only accept 1.12.1
            {
                sender.Writer.Write((byte)0x0);     // cmd, always 0
                sender.Writer.Write((byte)0x0);     // instant dc?
                sender.Writer.Write((byte)AuthenticationResult.WrongBuild);
            }
            else
            {
                // do SRP6 calculation and send back the server logon challenge, asking client for proof

                /*
                    uint8   cmd;
                    uint8   error;
                    uint8   unk2;
                    uint8   B[32]; -- server's public value
                    uint8   g_len; -- always 1
                    uint8   g;     -- 7
                    uint8   N_len; -- always 32
                    uint8   N[32]; -- always 0894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7 ;; joining the cool emu club
                    uint8   s[32]; -- Salt, a random value
                    uint8   unk3[16];
                    uint8   unk4;
                 */
                
                SRP6 srp = new SRP6(account.Identity, account.Password);
                sender.SRP = srp;

                sender.Writer.Write((byte)0x0);
                sender.Writer.Write((byte)AuthenticationResult.Succes);
                sender.Writer.Write((byte)0x0);
                sender.Writer.Write(srp.B.ToFixedByteArray().Pad(32));
                sender.Writer.Write((byte)0x1); // todo: implement flexible generator
                sender.Writer.Write((byte)0x7);
                sender.Writer.Write((byte)32);  // todo: implement flexible mod
                sender.Writer.Write(srp.Modulus.ToFixedByteArray().Pad(32));
                sender.Writer.Write(srp.Salt.ToFixedByteArray().Pad(32));
                sender.Writer.Write(new byte[16]);
                sender.Writer.Write((byte)0x0);

                sender.Writer.Flush();
            }
            
        }

        public void HandleLogonProof(ClientLogonProofPacket packet, WoWClient sender)
        {
            sender.SRP.A = packet.A;
            sender.SRP.M1 = packet.M1;

            /*  if(!sender.SRP.Authenticate)
              {
                  // Wrong password, the trip ends here.

                  sender.Writer.Write((byte)0x1);     // cmd, always 0
                  sender.Writer.Write((byte)0x0);     // instant dc?
                  sender.Writer.Write((byte)AuthenticationResult.WrongPassword);
                  return;
              }*/

            Log.Debug("GM1: " + sender.SRP.GenerateM1().ToByteArray().ToHexString());
            Log.Debug("M2:  " + sender.SRP.M2.ToByteArray().Pad(20).ToHexString());

            // todo: update session key
            sender.Writer.Write((byte)0x1);
          //  sender.Writer.Write((byte)0x0);
            sender.Writer.Write((byte)AuthenticationResult.Succes); // -- not a thing?
            sender.Writer.Write(sender.SRP.M2.ToByteArray().Pad(20));
            sender.Writer.Write((uint)0x0); // uint?
            sender.Writer.Write((uint)0x0); // uint?
            sender.Writer.Write((uint)0x0); // uint?
        }

        public void Start()
        {
            listener.Start();

            while (true)
            {
                var client = new WoWClient(listener.AcceptTcpClient());

                while(client.Connected)
                {
                    var packet = client.ReadAuthPacket();
                    HandleAuthPacket(packet, client);
                }
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            LogonServer logon = new LogonServer()
            {
                Provider = new TempAccountProvider()
            };

            logon.Start();

            Console.WriteLine("Server terminated.  Gently caress your keyboard to terminate.");
            Console.ReadLine();
        }
    }
}
