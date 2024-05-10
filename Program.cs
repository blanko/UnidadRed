// using System; // Se agrega automaticamente, no se si es por el tipo de proyecto
// using System.IO; // IDE0005: Using directive is unnecessary
using System.Security.Cryptography; // Usado para: Aes, CryptoStream, ICryptoTransform
using Microsoft.Win32; // Usado para: RegistryKey
using System.Text; // Usado para: Encoding
using System.Text.Json; // Usado para: JsonSerializer
using System.Runtime.InteropServices; // Usado para: StructLayout

namespace UnidadRed;

class Program
{
    // Clave y vector de inicialización como propiedades estáticas
    public static byte[] Key { get; } = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // Clave AES-256
    public static byte[] IV { get; } = Encoding.UTF8.GetBytes("1234567890123456"); // IV AES-16

    static void Main(string[] args)
    {
        /** 
            Descartado porque es muy dificil, por ahora, hacer que no de una advertencia sin dividirlo en muchas lineas.
        */
        // string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName; // Dereference of a possibly null reference.CS8602

        // Usar el directorio actual como predeterminado
        string exePath = Environment.GetCommandLineArgs()[0];
        string exeName = Path.GetFileName(exePath);


        Console.WriteLine("Ejecutando: " + exePath);

#if WINDOWS
        // Registro para autoejecución
        RegistryKey? key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        if (key != null)
        {
            key.SetValue("UnidadRed", $"\"{exePath}\"");
            key.Close();
        }
#endif

        // Obtener el directorio y avitar todas las advertencia de nullable
        string? directory = Path.GetDirectoryName(exePath) ?? string.Empty;
        // string? configPath = string.Empty;

        // if (directory != null)
        string? configPath = Path.Combine(directory, "configuracion.config");


        // Comprobación y actualización de configuración
        if (args.Length >= 4)
        {
            Console.WriteLine("Preparando la configuracion");
            // Actualizar configuración aquí
            ActualizarConfiguracion(configPath, args[0], args[1], args[2], args[3]);
        }


        // Leer y procesar el archivo .config
        if (File.Exists(configPath))
        {
            var config = LeerConfiguracion(configPath);
            // Montar unidad de red aquí usando 'config'
            if (config != null)
            {
                ConectarUnidadRed(config.Unidad, config.Ruta, config.Usuario, config.Contraseña);
            }
        }
        else
        {
            return; // Solo dentro de MAIN. Sale del Main, terminando el programa de forma natural
            // Environment.Exit(1); // Termina el programa con un código de estado 1 para indicar un error
        }

    }

    public static void ConectarUnidadRed(string unidad, string rutaRemota, string usuario, string contraseña)
    {
        NETRESOURCE netResource = new NETRESOURCE
        {
            lpLocalName = unidad,
            lpRemoteName = rutaRemota
        };

        int result = WNetAddConnection2(netResource, contraseña, usuario, 0);

        if (result != 0)
        {
            throw new InvalidOperationException("Error al conectar la unidad de red: " + result);
        }
        else
        {
            Console.WriteLine("Unidad de red conectada exitosamente.");
        }
    }

    static Configuracion? LeerConfiguracion(string configPath)
    {
        try
        {
            // Leer el archivo cifrado
            byte[] encryptedData = File.ReadAllBytes(configPath);

            // Descifrar los datos
            string jsonString = DecryptStringFromBytes_Aes(encryptedData, Key, IV);

            // Deserializar JSON a la clase Configuracion
            if (jsonString == null)
                throw new ArgumentNullException(nameof(jsonString), "El parámetro no puede ser nulo.");


            Configuracion config = JsonSerializer.Deserialize<Configuracion>(jsonString);

            return config;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error al leer la configuración: " + ex.Message);
            return null;
        }
    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        string? plaintext = null;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }

    static void ActualizarConfiguracion(string configPath, string unidad, string ruta, string usuario, string contraseña)
    {
        try
        {
            // Crear una instancia de Configuracion con los nuevos valores
            Configuracion config = new Configuracion
            {
                Unidad = unidad,
                Ruta = ruta,
                Usuario = usuario,
                Contraseña = contraseña
            };

            // Serializar la configuración a JSON
            string jsonString = JsonSerializer.Serialize(config);

            // Cifrar la cadena JSON
            byte[] encryptedData = EncryptStringToBytes_Aes(jsonString, Key, IV);

            // Guardar los datos cifrados en el archivo
            File.WriteAllBytes(configPath, encryptedData);

            Console.WriteLine("Configuración actualizada y guardada con éxito.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error al actualizar la configuración: " + ex.Message);
        }
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (Key == null || Key.Length <= 0)
            throw new ArgumentNullException("Key");
        if (IV == null || IV.Length <= 0)
            throw new ArgumentNullException("IV");

        byte[] encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class NETRESOURCE
    {
        public int dwScope = 0;
        public int dwType = RESOURCETYPE_DISK;
        public int dwDisplayType = 0;
        public int dwUsage = 0;
        public string? lpLocalName;
        public string? lpRemoteName;
        public string? lpComment = null;
        public string? lpProvider = null;
    }

    [DllImport("mpr.dll")]
    public static extern int WNetAddConnection2(NETRESOURCE netResource,
        string? password, string? username, int flags);

    public const int RESOURCETYPE_DISK = 0x00000001;
}

class Configuracion
{
    /** 
        Asegurarme de que todas las propiedades no nulables se inicialicen en el constructor de la clase. 
        Esto garantiza que no haya ningún estado inválido cuando se cree una instancia de la clase.
        Example: public string Unidad { get; set; } = string.Empty;
    **/

    // required para indicar que una propiedad debe ser inicializada antes de que el constructor termine
    public required string Unidad { get; set; }
    public required string Ruta { get; set; }
    // Le indico que puede ser nullable, sino da error de compilador en Net Core 8
    public string? Usuario { get; set; }
    public string? Contraseña { get; set; }
}
