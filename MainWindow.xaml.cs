using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.IO;

namespace AES
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private void encryptButton_Click(object sender, RoutedEventArgs e)
        {
            string str = putTextBox.Text;

            UnicodeEncoding asen = new UnicodeEncoding();
            ASCIIEncoding ascii = new ASCIIEncoding();
            // Key
            byte[] key = new byte[16];
            int padNum = 0;
            string keystr;
            if (16 < keyBox.GetLineLength(0))
            {
                MessageBox.Show("Key too long...Only use 16 bytes");
                return;
            }
            else if (16 > keyBox.GetLineLength(0))
            {
                padNum = 16 - keyBox.GetLineLength(0);
                keystr = keyBox.Text;
                for (int i = 0; i < padNum; i++)
                {
                    keystr += "x";
                }
                key = ascii.GetBytes(keystr);
            }
            else
            {
                key = ascii.GetBytes(keyBox.Text);
            }

            // Encrypt the string to an array of bytes.
            byte[] encrypted;
            byte[] IV;
            // Time analysis of encryption
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.ECB;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(str);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);
            string output = System.Convert.ToBase64String(combinedIvCt);
            // combinedIvCt is now the encrypted message
            putTextBox.Text = output;
        }
        private void TextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }

        private void TextBox_GotMouseCapture(object sender, RoutedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }

        private void TextBox_IsMouseCaptureWithinChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }
        private void KeyBox_GotFocus(object sender, RoutedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }

        private void KeyBox_GotMouseCapture(object sender, MouseEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }

        private void KeyBox_IsMouseCaptureWithinChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            TextBox textBox = (TextBox)sender;

            textBox.SelectAll();
        }

        private void decryptButton_Click(object sender, RoutedEventArgs e)
        {
            // str will be used to print out the decrypted text in the end
            string str = null;

            // AES decrypt part
            using (Aes aesAlg = Aes.Create())
            {
                UnicodeEncoding asen = new UnicodeEncoding();
                ASCIIEncoding ascii = new ASCIIEncoding();
                byte[] key = new byte[16];
                int padNum = 0;
                string keystr = "";
                if (16 < keyBox.GetLineLength(0))
                {
                    MessageBox.Show("Key too long...Only use 16 bytes");
                    return;
                }
                else if (16 > keyBox.GetLineLength(0))
                {
                    padNum = 16 - keyBox.GetLineLength(0);
                    keystr = keyBox.Text;
                    for (int i = 0; i < padNum; i++)
                    {
                        keystr += "x";
                    }
                    key = ascii.GetBytes(keystr);
                }
                else
                {
                    key = ascii.GetBytes(keyBox.Text);
                }
                byte[] IV;
                byte[] encryptedReceive = System.Convert.FromBase64String(putTextBox.Text);
                aesAlg.Key = key;
                IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[encryptedReceive.Length - IV.Length];

                Array.Copy(encryptedReceive, IV, IV.Length);
                Array.Copy(encryptedReceive, IV.Length, cipherText, 0, cipherText.Length);
                
                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.ECB;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                
                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            try
                            {
                                str = srDecrypt.ReadToEnd();
                            }
                            catch (Exception ex)
                            {
                                MessageBox.Show("That key is incorrect, and this program is unable to recover. Please restart.");
                                System.Environment.Exit(0);
                            }
                        }
                    }
                }


            }

            putTextBox.Text = str;
        }
    }
}
