using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

class UDPClient
{
    static void Main(string[] args)
    {
        using var clientSocket = new UdpClient();
        var serverEndpoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8888);
        clientSocket.Connect(serverEndpoint);

        byte[] publicKey = clientSocket.Receive(ref serverEndpoint);

        string message = "Olá server!";
        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);

        using var rsa = new RSACryptoServiceProvider(4096);
        rsa.ImportRSAPublicKey(publicKey, out _);
        byte[] encryptedData = rsa.Encrypt(messageBytes, true);

        clientSocket.Send(encryptedData, encryptedData.Length);

        clientSocket.Close();
    }
}
