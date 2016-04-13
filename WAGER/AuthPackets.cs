using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Numerics;

namespace WAGER
{
    enum AuthenticationResult : byte
    {
        Succes = 0x00,
        Banned = 0x03,
        UnkAccount = 0x04,
        WrongPassword = 0x05,
        AccountInuse = 0x06,
        PayMore = 0x07, // 0x07 "preorder time limit" ??
        ServerFull = 0x08,
        WrongBuild = 0x09,
    }

    enum PacketType : byte
    {
        BitchCantParsePackets = 0xFF,
        LogonChallenge = 0x0,
        LogonProof = 0x1,
        ReconnectChallenge = 0x2,
        ReconnectProof = 0x3,
        RealmList = 0x10,
        TransferInit = 0x30 // patch stuff?
    }

    class AuthPacket
    {
        public PacketType Type;
    }

    class ClientLogonChallengePacket : AuthPacket
    {
        public byte Error;
        public ushort Size;
        public string GameName;
        public byte Version1;
        public byte Version2;
        public byte Version3;
        public ushort Build;
        public string Platform;
        public string OS;
        public string Country;
        public uint TimezoneBIAS;
        public IPAddress IP;
        public byte ILength;
        public string Identity; 
    }

    class ServerLogonChallengePacket : AuthPacket
    {
        public byte Error;
        public byte Unk2;
        public BigInteger B; // 32-bits long
        public byte GLength; // 1, always use 7
        public byte G; // 7
        public byte NLength;
        public BigInteger N; // 32-bits
        public BigInteger Salt; // 32 bits
        public byte Unk3; // 16 bit
        public byte Unk4;
    }

    class ClientLogonProofPacket : AuthPacket
    {
        public BigInteger A; // 32 bits
        public BigInteger M1; // 20 bits
        public BigInteger CrcHash; // 20 bits
        public byte NumerOfKeys; // unk, 0
        public byte Unk;
    }
}
