using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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

namespace CryptoServicing
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

        /// <summary>
        /// Method that fires when the window is loaded
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            //*****************************************************************************************************************************//
            //************************************************************ AES ************************************************************//
            //fill the key size drop down
            foreach (int item in Enum.GetValues(typeof(AESKeySize)))
            {
                this.cboAESKeySize.Items.Add(new ListItem(((AESKeySize)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboAESKeySize.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(CipherMode)))
            {
                if (item != (int)CipherMode.CTS && item != (int)CipherMode.OFB)
                    this.cboAESMode.Items.Add(new ListItem(((CipherMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboAESMode.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(PaddingMode)))
            {
                if (item != (int)PaddingMode.None)
                    this.cboAESPadding.Items.Add(new ListItem(((PaddingMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboAESPadding.SelectedIndex = 0;
            //*****************************************************************************************************************************//
            //*****************************************************************************************************************************//
            //****************************************************** RijndaelManaged ******************************************************//
            //fill the key size drop down
            foreach (int item in Enum.GetValues(typeof(RMKeySize)))
            {
                this.cboRMKeySize.Items.Add(new ListItem(((RMKeySize)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboRMKeySize.SelectedIndex = 0;

            //fill the RM cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(CipherMode)))
            {
                if (item != (int)CipherMode.CTS && item != (int)CipherMode.OFB)
                    this.cboRMMode.Items.Add(new ListItem(((CipherMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboRMMode.SelectedIndex = 0;

            //fill the RM cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(PaddingMode)))
            {
                if (item != (int)PaddingMode.None)
                    this.cboRMPadding.Items.Add(new ListItem(((PaddingMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboRMPadding.SelectedIndex = 0;
            //*****************************************************************************************************************************//
            //*****************************************************************************************************************************//
            //************************************************************ DES ************************************************************//
            //fill the key size drop down
            foreach (int item in Enum.GetValues(typeof(DESKeySize)))
            {
                this.cboDESKeySize.Items.Add(new ListItem(((DESKeySize)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboDESKeySize.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(CipherMode)))
            {
                if (item != (int)CipherMode.CTS && item != (int)CipherMode.OFB)
                    this.cboDESMode.Items.Add(new ListItem(((CipherMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboDESMode.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(PaddingMode)))
            {
                if (item != (int)PaddingMode.None)
                    this.cboDESPadding.Items.Add(new ListItem(((PaddingMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboDESPadding.SelectedIndex = 0;
            //*****************************************************************************************************************************//
            //*****************************************************************************************************************************//
            //******************************************************** Triple DES *********************************************************//
            //fill the key size drop down
            foreach (int item in Enum.GetValues(typeof(TripleDESKeySize)))
            {
                this.cboTripleDESKeySize.Items.Add(new ListItem(((TripleDESKeySize)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboTripleDESKeySize.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(CipherMode)))
            {
                if (item != (int)CipherMode.CTS && item != (int)CipherMode.OFB)
                    this.cboTripleDESMode.Items.Add(new ListItem(((CipherMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboTripleDESMode.SelectedIndex = 0;

            //fill the aes cipher mode drop down
            foreach (int item in Enum.GetValues(typeof(PaddingMode)))
            {
                if (item != (int)PaddingMode.None)
                    this.cboTripleDESPadding.Items.Add(new ListItem(((PaddingMode)item).ToString().Replace("_", " ").Trim(), item));
            }
            this.cboTripleDESPadding.SelectedIndex = 0;
            //*****************************************************************************************************************************//

        }

        #region "SHA1"
        /// <summary>
        /// Event that fires when the sha1 encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        //private void btnSHA1Encrypt_Click(object sender, RoutedEventArgs e)
        //{
        //    byte[] byteHash = null;
        //    byte[] byteValue = null;

        //    byteValue = System.Text.Encoding.ASCII.GetBytes(this.txtSHA1PasswordToHash.Text);

        //    // Compute SHA1 hashed bytes
        //    SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
        //    byteHash = sha1.ComputeHash(byteValue);
        //    sha1.Clear();

        //    string encryptedPassword = Convert.ToBase64String(byteHash);

        //    this.txtSHA1EncryptedText.Text = encryptedPassword;
        //}

        private void btnSHA1Encrypt_Click(object sender, RoutedEventArgs e)
        {
            var byteValue = Encoding.ASCII.GetBytes(this.txtSHA1PasswordToHash.Text);

            // Compute SHA1 hashed bytes
            var sha256 = SHA256Managed.Create();
            var byteHash = sha256.ComputeHash(byteValue);
            sha256.Clear();

            string encryptedPassword = Convert.ToBase64String(byteHash);

            this.txtSHA1EncryptedText.Text = encryptedPassword;


            //string strToHash = (STR_CSI_TVR + token + secureKey.ToString()).ToUpper(Thread.CurrentThread.CurrentCulture);

            //var hex = new StringBuilder(hash.Length * 2);
            //foreach (var b in hash)
            //{
            //    hex.AppendFormat("{0:x2}", b);
            //}

        }

        /// <summary>
        /// Event that fires when the sha1 reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnSHA1Reset_Click(object sender, RoutedEventArgs e)
        {
            this.txtSHA1PasswordToHash.Text = String.Empty;
            this.txtSHA1EncryptedText.Text = String.Empty;
        }
        #endregion

        #region "MD5"
        /// <summary>
        /// Event that fires when the MD5 encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnMD5Encrypt_Click(object sender, RoutedEventArgs e)
        {
            byte[] byteHash = null;
            byte[] byteValue = null;

            byteValue = System.Text.Encoding.ASCII.GetBytes(this.txtMD5PasswordToHash.Text);

            // Compute MD5 hashed bytes
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            byteHash = md5.ComputeHash(byteValue);
            md5.Clear();

            string encryptedPassword = Convert.ToBase64String(byteHash);

            this.txtMD5EncryptedText.Text = encryptedPassword;
        }

        /// <summary>
        /// Event that fires when the md5 reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnMD5Reset_Click(object sender, RoutedEventArgs e)
        {
            this.txtMD5PasswordToHash.Text = String.Empty;
            this.txtMD5EncryptedText.Text = String.Empty;
        }
        #endregion

        #region "AES"
        private enum AESKeySize
        {
            //_64_bit = 64, NOT VALID
            _128_bit = 128,
            _192_bit = 192,
            _256_bit = 256,
            //_512_bit = 512 NOT VALID
        }

        /// <summary>
        /// Event that fires when the aes encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnAESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            byte[] cipherText;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = ((ListItem)this.cboAESKeySize.SelectedItem).Value;
                aes.Mode = (CipherMode)((ListItem)this.cboAESMode.SelectedItem).Value;
                aes.Padding = (PaddingMode)((ListItem)this.cboAESPadding.SelectedItem).Value;
                //aes.BlockSize = ;

                aes.GenerateIV();
                this.txtAESIV.Text = Convert.ToBase64String(aes.IV);

                //generate the key and insert it into the text box
                aes.GenerateKey();
                this.txtAESPassword.Text = Convert.ToBase64String(aes.Key);

                byte[] byteInputText = Convert.FromBase64String(this.txtAESInput.Text);

                using (ICryptoTransform crypto = aes.CreateEncryptor())
                {
                    cipherText = crypto.TransformFinalBlock(byteInputText, 0, byteInputText.Length);
                    aes.Clear();
                }
            }

            this.txtAESOutput.Text = Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Event that fires when the aes decrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnAESDecrypt_Click(object sender, RoutedEventArgs e)
        {
            byte[] byteOutputText = null;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = ((ListItem)this.cboAESKeySize.SelectedItem).Value;
                aes.Mode = (CipherMode)((ListItem)this.cboAESMode.SelectedItem).Value;
                aes.Padding = (PaddingMode)((ListItem)this.cboAESPadding.SelectedItem).Value;
                //aes.BlockSize = ;

                //use the previously generated key
                aes.Key = Convert.FromBase64String(this.txtAESPassword.Text);

                //use the previously generated Initialization Vector (IV)
                aes.IV = Convert.FromBase64String(this.txtAESIV.Text);

                //now get the output text
                byte[] cipherText = Convert.FromBase64String(this.txtAESOutput.Text);

                using (ICryptoTransform crypto = aes.CreateDecryptor())
                {
                    byteOutputText = crypto.TransformFinalBlock(cipherText, 0, cipherText.Length);
                    aes.Clear();
                }
            }

            this.txtAESOutput.Text += "\r\n\r\n Decrypted Text: \r\n\r\n";
            this.txtAESOutput.Text += Convert.ToBase64String(byteOutputText);
        }

        /// <summary>
        /// Event that fires when the aes reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnAESReset_Click(object sender, RoutedEventArgs e)
        {
            this.cboAESKeySize.SelectedIndex = 0;
            this.cboAESMode.SelectedIndex = 0;
            this.cboAESPadding.SelectedIndex = 0;
            this.txtAESPassword.Text = string.Empty;
            this.txtAESIV.Text = string.Empty;
            this.txtAESInput.Text = string.Empty;
            this.txtAESOutput.Text = string.Empty;
        }

        /// <summary>
        /// Event that fires when the text is changed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void txtAESInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            //enable and disable the encrypt button depending on if there's text
            if (string.IsNullOrEmpty(this.txtAESInput.Text))
            {
                this.btnAESEncrypt.IsEnabled = false;
                this.btnAESDecrypt.IsEnabled = false;
            }
            else
            {
                this.btnAESEncrypt.IsEnabled = true;
                this.btnAESDecrypt.IsEnabled = true;
            }
        }
        #endregion

        #region "RijndaelManaged"
        /// <summary>
        /// This region is really the same as AES because RijndaelManaged is supposed to be an implementation of AES
        /// </summary>
        
        private enum RMKeySize
        {
            //_64_bit = 64, NOT VALID
            _128_bit = 128,
            _192_bit = 192,
            _256_bit = 256,
            //_512_bit = 512 NOT VALID
        }

        private void btnRMEncrypt_Click(object sender, RoutedEventArgs e)
        {
            byte[] cipherText;

            using (RijndaelManaged rm = new RijndaelManaged())
            {
                rm.KeySize = ((ListItem)this.cboRMKeySize.SelectedItem).Value;
                rm.Mode = (CipherMode)((ListItem)this.cboRMMode.SelectedItem).Value;
                rm.Padding = (PaddingMode)((ListItem)this.cboRMPadding.SelectedItem).Value;
                //RM.BlockSize = ;

                rm.GenerateIV();
                this.txtRMIV.Text = Convert.ToBase64String(rm.IV);

                //generate the key and insert it into the text box
                rm.GenerateKey();
                this.txtRMPassword.Text = Convert.ToBase64String(rm.Key);

                byte[] byteInputText = Convert.FromBase64String(this.txtRMInput.Text);

                using (ICryptoTransform crypto = rm.CreateEncryptor())
                {
                    cipherText = crypto.TransformFinalBlock(byteInputText, 0, byteInputText.Length - 1);
                    rm.Clear();
                }
            }

            this.txtRMOutput.Text = Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Event that fires when the rm decrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnRMDecrypt_Click(object sender, RoutedEventArgs e)
        {

        }

        /// <summary>
        /// Event that fires when the rm reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnRMReset_Click(object sender, RoutedEventArgs e)
        {
            this.cboRMKeySize.SelectedIndex = 0;
            this.cboRMMode.SelectedIndex = 0;
            this.cboRMPadding.SelectedIndex = 0;
            this.txtRMPassword.Text = string.Empty;
            this.txtRMIV.Text = string.Empty;
            this.txtRMInput.Text = string.Empty;
            this.txtRMOutput.Text = string.Empty;
        }

        /// <summary>
        /// Event that fires when the rm input text changes
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void txtRMInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            //enable and disable the encrypt button depending on if there's text
            if (string.IsNullOrEmpty(this.txtRMInput.Text))
            {
                this.btnRMEncrypt.IsEnabled = false;
                this.btnRMDecrypt.IsEnabled = false;
            }
            else
            {
                this.btnRMEncrypt.IsEnabled = true;
                this.btnRMDecrypt.IsEnabled = true;
            }
        }
        #endregion

        #region "DES"
        private enum DESKeySize
        {
            //_32_bit = 32, NOT VALID
            _64_bit = 64
            //_128_bit = 128 NOT VALID
        }

        /// <summary>
        /// Event that fires when the des encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();

            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.KeySize = ((ListItem)this.cboDESKeySize.SelectedItem).Value;
            des.Mode = (CipherMode)((ListItem)this.cboDESMode.SelectedItem).Value;
            des.Padding = (PaddingMode)((ListItem)this.cboDESPadding.SelectedItem).Value;
            //des.BlockSize = ;

            des.GenerateIV();
            this.txtDESIV.Text = Convert.ToBase64String(des.IV);

            //generate the key and insert it into the text box
            des.GenerateKey();
            this.txtDESPassword.Text = Convert.ToBase64String(des.Key);

            byte[] byteInputText = encoding.GetBytes(this.txtDESInput.Text);

            byte[] cipherText;
            using (ICryptoTransform crypto = des.CreateEncryptor())
            {
                cipherText = crypto.TransformFinalBlock(byteInputText, 0, byteInputText.Length - 1);
                des.Clear();
            }

            this.txtDESOutput.Text = Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Event that fires when the des decrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDESDecrypt_Click(object sender, RoutedEventArgs e)
        {

        }

        /// <summary>
        /// Event that fires when the des reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDESReset_Click(object sender, RoutedEventArgs e)
        {
            this.cboDESKeySize.SelectedIndex = 0;
            this.cboDESMode.SelectedIndex = 0;
            this.cboDESPadding.SelectedIndex = 0;
            this.txtDESPassword.Text = string.Empty;
            this.txtDESIV.Text = string.Empty;
            this.txtDESInput.Text = string.Empty;
            this.txtDESOutput.Text = string.Empty;
        }

        /// <summary>
        /// Event that fires when the text changes in des input
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void txtDESInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            //enable and disable the encrypt button depending on if there's text
            if (string.IsNullOrEmpty(this.txtDESInput.Text))
            {
                this.btnDESEncrypt.IsEnabled = false;
                this.btnDESDecrypt.IsEnabled = false;
            }
            else
            {
                this.btnDESEncrypt.IsEnabled = true;
                this.btnDESDecrypt.IsEnabled = true;
            }
        }
        #endregion

        #region "TripleDES"
        private enum TripleDESKeySize
        {
            //_64_bit = 64, NOT VALID
            _128_bit = 128,
            _192_bit = 192
            //_256_bit = 256 NOT VALID
        }

        /// <summary>
        /// Event that fires when tripledes encrypt is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnTripleDESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();

            TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider();
            tripleDES.KeySize = ((ListItem)this.cboTripleDESKeySize.SelectedItem).Value;
            tripleDES.Mode = (CipherMode)((ListItem)this.cboTripleDESMode.SelectedItem).Value;
            tripleDES.Padding = (PaddingMode)((ListItem)this.cboTripleDESPadding.SelectedItem).Value;
            //des.BlockSize = ;

            tripleDES.GenerateIV();
            this.txtTripleDESIV.Text = Convert.ToBase64String(tripleDES.IV);

            //generate the key and insert it into the text box
            tripleDES.GenerateKey();
            this.txtTripleDESPassword.Text = Convert.ToBase64String(tripleDES.Key);

            byte[] byteInputText = encoding.GetBytes(this.txtTripleDESInput.Text);

            byte[] cipherText;
            using (ICryptoTransform crypto = tripleDES.CreateEncryptor())
            {
                cipherText = crypto.TransformFinalBlock(byteInputText, 0, byteInputText.Length - 1);
                tripleDES.Clear();
            }

            this.txtTripleDESOutput.Text = Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Event that fires when the triple des decrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnTripleDESDecrypt_Click(object sender, RoutedEventArgs e)
        {

        }

        /// <summary>
        /// Event that fires when the triple des reset button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnTripleDESReset_Click(object sender, RoutedEventArgs e)
        {
            this.cboTripleDESKeySize.SelectedIndex = 0;
            this.cboTripleDESMode.SelectedIndex = 0;
            this.cboTripleDESPadding.SelectedIndex = 0;
            this.txtTripleDESPassword.Text = string.Empty;
            this.txtTripleDESIV.Text = string.Empty;
            this.txtTripleDESInput.Text = string.Empty;
            this.txtTripleDESOutput.Text = string.Empty;
        }

        /// <summary>
        /// Event that fires when the triple des input button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void txtTripleDESInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            //enable and disable the encrypt button depending on if there's text
            if (string.IsNullOrEmpty(this.txtTripleDESInput.Text))
            {
                this.btnTripleDESEncrypt.IsEnabled = false;
                this.btnTripleDESDecrypt.IsEnabled = false;
            }
            else
            {
                this.btnTripleDESEncrypt.IsEnabled = true;
                this.btnTripleDESDecrypt.IsEnabled = true;
            }
        }
        #endregion

        #region "DSA"
        /// <summary>
        /// Event that fires when the dsa encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnDSAEncrypt_Click(object sender, RoutedEventArgs e)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();

            CspParameters parameters = new CspParameters();
            parameters.Flags = CspProviderFlags.UseMachineKeyStore;

            DSACryptoServiceProvider dsa = new DSACryptoServiceProvider(parameters);
            dsa.KeySize = ((ListItem)this.cboDESKeySize.SelectedItem).Value;
            

            //dsa.
            byte[] byteInputText = encoding.GetBytes(this.txtDESInput.Text);

            byte[] cipherText;
            //using (ICryptoTransform crypto = dsa.CreateEncryptor())
            //{
            //    cipherText = crypto.TransformFinalBlock(byteInputText, 0, byteInputText.Length - 1);
            //    dsa.Clear();
            //}

            //this.txtDESOutput.Text = Convert.ToBase64String(cipherText);
        }
        #endregion

        #region "RNG"
        /// <summary>
        /// Event that fires when the rng encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnRNGEncrypt_Click(object sender, RoutedEventArgs e)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        }
        #endregion

        #region "RSA"
        /// <summary>
        /// Event that fires when the rsa encrypt button is clicked
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnRSAEncrypt_Click(object sender, RoutedEventArgs e)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();

            CspParameters parameters = new CspParameters();
            parameters.Flags = CspProviderFlags.UseMachineKeyStore;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.KeySize = ((ListItem)this.cboDESKeySize.SelectedItem).Value;
            //rsa.Encrypt
            

        }
        #endregion

        #region "Utility Methods"

        #endregion
    }

    #region "ListItem Class"
    class ListItem
    {
        public string Description = "";
        public int Value = 0;

        public ListItem(string description, int value)
        {
            Description = description;
            Value = value;
        }

        public override string ToString() 
        {
            return this.Description;
        }
    }
    #endregion
}
