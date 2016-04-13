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
    class WoWClient
    {
        private TcpClient client;
        public BinaryReader Reader;
        public BinaryWriter Writer;

        // encapsulate authentication state
        public SRP6 SRP;

        public WoWClient(TcpClient client)
        {
            this.client = client;
            this.Reader = new BinaryReader(client.GetStream());
            this.Writer = new BinaryWriter(client.GetStream());
        }

        public bool Connected
        {
            get
            {
                return client.Connected;
            }
        }

        public AuthPacket ReadAuthPacket()
        {
            //  if (!client.GetStream().DataAvailable)
            //      throw new EndOfStreamException("No auth packets to read on the stream.");)

            byte b = Reader.ReadByte();
            var type = (PacketType)b;

            Log.Debug("In " + type.ToString());

            if (type == PacketType.LogonChallenge)
                return ReadLogonChallengePacket();
            else if (type == PacketType.LogonProof)
                return ReadLogonProofPacket();



            return null; // unk

        }

        public ClientLogonChallengePacket ReadLogonChallengePacket()
        {
            return new ClientLogonChallengePacket()
            {
                Type = PacketType.LogonChallenge,
                Error = Reader.ReadByte(),
                Size = Reader.ReadUInt16(),
                GameName = Encoding.ASCII.GetString(Reader.ReadBytes(4)),
                Version1 = Reader.ReadByte(),
                Version2 = Reader.ReadByte(),
                Version3 = Reader.ReadByte(),
                Build = Reader.ReadUInt16(),
                Platform = Encoding.ASCII.GetString(Reader.ReadBytes(4)),
                OS = Encoding.ASCII.GetString(Reader.ReadBytes(4)),
                Country = Encoding.ASCII.GetString(Reader.ReadBytes(4)),
                TimezoneBIAS = Reader.ReadUInt32(),
                IP = new IPAddress(Reader.ReadUInt32()),
                Identity = Encoding.ASCII.GetString(Reader.ReadBytes(Reader.ReadByte()))
            };
        }

        public ClientLogonProofPacket ReadLogonProofPacket()
        {
            var ra = Reader.ReadBytes(32).Concat(new byte[] { 0x0 }).ToArray();
            var rm1 = Reader.ReadBytes(20).Concat(new byte[] { 0x0 }).ToArray();
            var rcrc = Reader.ReadBytes(20).Concat(new byte[] { 0x0 }).ToArray();

            Log.Debug("A:  " + ra.ToHexString());
            Log.Debug("M1: " + rm1.ToHexString());

            return new ClientLogonProofPacket()
            {
                Type = PacketType.LogonProof,
                A = new BigInteger(ra),
                M1 = new BigInteger(rm1),
                CrcHash = new BigInteger(rcrc),
                NumerOfKeys = Reader.ReadByte(),
                Unk = Reader.ReadByte() // security flags?
            };
        }
    }

}
