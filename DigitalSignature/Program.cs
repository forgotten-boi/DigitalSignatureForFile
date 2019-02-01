using SautinSoft.Document;
using SautinSoft.Document.Drawing;
using System;
using System.Linq;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Reflection.Metadata;
using System.IO;
using Spire.Pdf.Security;
using Spire.Pdf;

namespace DigitalSignature
{
    /// <summary>
    /// Reference https://sautinsoft.com/products/document/examples/digital-signature-net-csharp-vb.php
    /// </summary>
    partial class Program
    {

        static RSAParameters _privateKey { get; set; }
        static RSAParameters _publicKey { get; set; }
        const string signaturePath = @"..\..\..\signature.zn";
        

        static void Main(string[] args)
        {
            string loadPath = @"..\..\..\Pitambar_Resume.docx";

            //ShaDigitalSign
            //ShaDigitalSignature(loadPath);

            //X509 Digital Signature: Needs some modification to work
            //X509DigitalSign(loadPath);

            //For calling SpirePdf
            //var thesisPdfPath = @"..\..\..\Thesis Cover.pdf";
            //SpireSignDoc(thesisPdfPath);

            //Md5
            //SignDataMd5(LoadPath);

            //SautinSoft
            //SignDocument(LoadPath)

            //X509Digital Certificate

        }

        #region X509 Digital Signature
        public static void X509DigitalSign(string loadPath)
        {
            try
            {
                // Sign text
                byte[] signature = Sign(loadPath, "CN=pjha");
                
                // Verify signature. Testcert.cer corresponds to "cn=my cert subject"
                if (Verify(loadPath, signature, @"C:\testcert.cer"))
                {
                    Console.WriteLine("Signature verified");
                }
                else
                {
                    Console.WriteLine("ERROR: Signature not valid!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("EXCEPTION: " + ex.Message);
            }

            Console.ReadKey();
        }
        #endregion


        #region Sha digital Sign

        public static void ShaDigitalSignature(string loadPath)
        {
            //Converting document to byte
            var document = DocumentToByte(loadPath);

            //Generate hash data
            byte[] hashedDocument;
            using (var sha256 = SHA256.Create())
            {
                hashedDocument = sha256.ComputeHash(document);
            }

            //Generate and assign private and public key
            AssignNewKey();

            //Generate signature
            var signature = SignData(hashedDocument);

            //Another file
            byte[] crashedDocument;
            var crashDoc = DocumentToByte(@"..\..\..\Pitambar_Resume Javra for external use.docx");

            using (var sha256 = SHA256.Create())
            {
                crashedDocument = sha256.ComputeHash(crashDoc);
            }

            //Reading signature from file
            var sign = DocumentToByte(signaturePath);

            var verified = VerifySignature(crashedDocument, sign);

            Console.WriteLine("Digital Signature");
            Console.WriteLine("---------------------------------------");
            Console.WriteLine();

            Console.WriteLine("   Original Text = " +
                Encoding.Default.GetString(document));

            Console.WriteLine();
            Console.WriteLine("   Digital Signature = " +
                Convert.ToBase64String(signature));

            Console.WriteLine();
            Console.WriteLine("Digital Signature Saved to Text File signature.txt");
            Console.WriteLine();
            Console.WriteLine("signature text:" + System.IO.File.ReadAllText(signaturePath));


            Console.WriteLine(verified
                ? "The digital signature has been correctly verified."
                : "The digital signature has NOT been correctly verified.");

            Console.ReadLine();
        }

        public static byte[] SignData(byte[] hashofDataToSign)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");
                var signature= rsaFormatter.CreateSignature(hashofDataToSign);
               
            
                File.WriteAllBytes(signaturePath, signature);
                return signature;
            }
        }

        public static bool VerifySignature(byte[] hashOfDataToSign, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(_publicKey);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");

                return rsaDeformatter.VerifySignature(hashOfDataToSign, signature);
            }
        }

        #endregion

        #region Custom Function

        public static void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }
        public static byte[] DocumentToByte(string filename)
        {
            using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                // Create a byte array of file stream length
                byte[] bytes = System.IO.File.ReadAllBytes(filename);
                //Read block of bytes from stream into the byte array
                fs.Read(bytes, 0, System.Convert.ToInt32(fs.Length));
                //Close the File Stream
                fs.Close();
                return bytes; //return the byte data
            }
        }
        #endregion

        #region 3rd party library SpireDoc
        public static string SpireSignDoc(string path)
        {
            var result = @"..\..\..\Thesis Cover_Signed.pdf";
            PdfDocument doc = new PdfDocument(path);
            PdfPageBase page = doc.Pages[0];

            PdfCertificate cert = new PdfCertificate(@"..\..\..\DigitalSignature.pfx", "Abc123!@#");

            PdfSignature signature = new PdfSignature(doc, page, cert, "demo");

            signature.ContactInfo = "Harry";
            signature.Certificated = true;
            
            signature.DocumentPermissions = PdfCertificationFlags.AllowFormFill;
            
            doc.SaveToFile(result);
            return result;
        }

        //public static bool VerifyDoc(string signedDoc, string distinguishedName)
        //{
        //    PdfDocument doc = new PdfDocument(signedDoc);
        //    PdfPageBase page = doc.Pages[0];
        //    PdfSignature pdfSignature = new PdfSignature(page,)
        //}
        #endregion

        #region 3rd party library SautinSoft
        public static string SignDocument(string loadPath)
        {
            string signedDoc = @"SignedDoc.pdf";

            //string signedDoc = "Pitambar_resume_Signed.pdf";
            DocumentCore documentCore = DocumentCore.Load(loadPath);

            Shape signatureShape = new Shape(documentCore, Layout.Floating(
                                    new HorizontalPosition(0f, LengthUnit.Millimeter, HorizontalPositionAnchor.LeftMargin),
                                    new VerticalPosition(0f, LengthUnit.Millimeter, VerticalPositionAnchor.TopMargin), new Size(1, 1)));
            ((FloatingLayout)signatureShape.Layout).WrappingStyle = WrappingStyle.InFrontOfText;
            signatureShape.Outline.Fill.SetEmpty();

            // Find a first paragraph and insert our Shape inside it.
            Paragraph firstPar = documentCore.GetChildElements(true).OfType<Paragraph>().FirstOrDefault();
            firstPar.Inlines.Add(signatureShape);


            // Picture which symbolizes a handwritten signature.
            Picture signaturePict = new Picture(documentCore, @"..\..\..\nishicon.ico");

            // Signature picture will be positioned:
            // 14.5 cm from Top of the Shape.
            // 4.5 cm from Left of the Shape.
            signaturePict.Layout = Layout.Floating(
               new HorizontalPosition(4.5, LengthUnit.Centimeter, HorizontalPositionAnchor.Page),
               new VerticalPosition(14.5, LengthUnit.Centimeter, VerticalPositionAnchor.Page),
               new Size(20, 10, LengthUnit.Millimeter));


            PdfSaveOptions options = new PdfSaveOptions();

            // Path to the certificate (*.pfx).
            options.DigitalSignature.CertificatePath = @"..\..\..\NewSignKey.pfx";

            // The password for the certificate.
            // Each certificate is protected by a password.
            // The reason is to prevent unauthorized the using of the certificate.
            options.DigitalSignature.CertificatePassword = "Abc123!@#";

            // Additional information about the certificate.
            options.DigitalSignature.Location = "Kathmandu";
            options.DigitalSignature.Reason = "for demo";
            options.DigitalSignature.ContactInfo = "pitambarzha@gmail.com";

            // Placeholder where signature should be visualized.
            options.DigitalSignature.SignatureLine = signatureShape;

            // Visual representation of digital signature.
            options.DigitalSignature.Signature = signaturePict;

            documentCore.Save(signedDoc, options);

            // Open the result for demonstation purposes.
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(signedDoc) { UseShellExecute = true });

            return "";
        }

        public static string DigitalSignature()
        {
            // Path to a loadable document.
            string loadPath = @"..\..\..\SqlServerDataTools.docx";
            string savePath = @"..\..\..\SignedSqlServerDataTools.pdf";

            DocumentCore dc = DocumentCore.Load(loadPath);

            // Create a new invisible Shape for the digital signature.
            // Place the Shape into top-left corner (0 mm, 0 mm) of page.
            Shape signatureShape = new Shape(dc, Layout.Floating(new HorizontalPosition(0f, LengthUnit.Millimeter, HorizontalPositionAnchor.LeftMargin),
                                    new VerticalPosition(0f, LengthUnit.Millimeter, VerticalPositionAnchor.TopMargin), new Size(1, 1)));
            ((FloatingLayout)signatureShape.Layout).WrappingStyle = WrappingStyle.InFrontOfText;
            signatureShape.Outline.Fill.SetEmpty();

            // Find a first paragraph and insert our Shape inside it.
            Paragraph firstPar = dc.GetChildElements(true).OfType<Paragraph>().FirstOrDefault();
            firstPar.Inlines.Add(signatureShape);

            // Picture which symbolizes a handwritten signature.
            Picture signaturePict = new Picture(dc, @"..\..\..\nishtechlogo.png");

            // Signature picture will be positioned:
            // 14.5 cm from Top of the Shape.
            // 4.5 cm from Left of the Shape.
            signaturePict.Layout = Layout.Floating(
               new HorizontalPosition(4.5, LengthUnit.Centimeter, HorizontalPositionAnchor.Page),
               new VerticalPosition(14.5, LengthUnit.Centimeter, VerticalPositionAnchor.Page),
               new Size(20, 10, LengthUnit.Millimeter));

            PdfSaveOptions options = new PdfSaveOptions();

            // Path to the certificate (*.pfx).
            options.DigitalSignature.CertificatePath = @"..\..\..\DigitalSignature.pfx";

            // The password for the certificate.
            // Each certificate is protected by a password.
            // The reason is to prevent unauthorized the using of the certificate.
            options.DigitalSignature.CertificatePassword = "Abc123!@#";
            options.EncryptionDetails.EncryptionAlgorithm = SautinSoft.Document.PdfEncryptionAlgorithm.RC4_128;

            // Additional information about the certificate.
            options.DigitalSignature.Location = "Kathmandu";
            options.DigitalSignature.Reason = "Digital Signature by Pitambar";
            options.DigitalSignature.ContactInfo = "pitambarzha@gmail.com";

            // Placeholder where signature should be visualized.
            options.DigitalSignature.SignatureLine = signatureShape;

            // Visual representation of digital signature.
            options.DigitalSignature.Signature = signaturePict;

            dc.Save(savePath, options);

            // Open the result for demonstation purposes.
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(savePath) { UseShellExecute = true });
            return savePath;
        }
        #endregion

      
        #region MD5 sign and verify


        public static void SignDataMd5(string loadPath)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                string hash = GetMd5Hash(md5Hash, loadPath);

                Console.WriteLine("The MD5 hash of " + loadPath + " is: " + hash + ".");

                Console.WriteLine("Verifying the hash...");
                var verified = VerifyMd5Hash(md5Hash, loadPath, hash);
                Console.WriteLine(verified
               ? "The hash value is same and hence correctly verified."
               : "The hash value is not same and hence has NOT been correctly verified.");
            }
            
        }

        //Return Md5Hash 
        static string GetMd5Hash(MD5 md5Hash, string fileName)
        {

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(System.IO.File.ReadAllBytes(fileName));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        static bool VerifyMd5Hash(MD5 md5Hash, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetMd5Hash(md5Hash, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        #endregion


    }
}
