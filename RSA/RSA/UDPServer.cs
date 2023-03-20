using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

class UDPServer
{
    static void Main(string[] args)
    {
        UdpClient serverSocket = new UdpClient(8888);
        IPEndPoint clientEndpoint = new IPEndPoint(IPAddress.Any, 0);

        // Etapa 1: Gerando chaves RSA
        using (var rsa = new RSACryptoServiceProvider(4096))
        {
            // Etapa 2: Exportando chave pública e chave privada
            byte[] publicKey = rsa.ExportRSAPublicKey();
            byte[] privateKey = rsa.ExportRSAPrivateKey();

            // Etapa 3: Enviando chave pública para o cliente
            serverSocket.Send(publicKey, publicKey.Length, clientEndpoint);

            // Etapa 4: Recebendo e descriptografando dados do cliente
            while (true)
            {
                byte[] encryptedData = serverSocket.Receive(ref clientEndpoint);
                byte[] decryptedData = rsa.Decrypt(encryptedData, true);

                string message = System.Text.Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine("Mensagem recebida: {0}", message);
            }
        }

        serverSocket.Close();
    }
}
