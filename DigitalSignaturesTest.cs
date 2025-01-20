//
// Copyright (c) 2001-2024 by Apryse Software Inc. All Rights Reserved.
//

// This is based on the DigitalSignatureTest code that can be downloaded from https://docs.apryse.com/core/samples#digitalsignatures
// You will also need the Apryse SDK, and a trial license, plus a Yubikey with a Certificate installed.

using System;
using System.Collections.Generic;
using pdftron;
using pdftron.PDF;
using pdftron.PDF.Annots;
using pdftron.SDF;
using pdftron.Crypto;
using System.Linq;
using Yubico.YubiKey;
using Yubico.YubiKey.Piv;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Yubico.YubiKey.Cryptography;
using System.IO;

namespace DigitalSignaturesTestCS
{
    class Class1
    {
        static string input_path = "../../../../../TestFiles/";
        static string output_path = "../../../../../TestFiles/Output/";


        static void CustomSigningAPIYubikey(string doc_path,
            string cert_field_name,
            string appearance_image_path,
            DigestAlgorithm.Type digest_algorithm_type,
            string output_path)
        {
            Console.Out.WriteLine("================================================================================");
            Console.Out.WriteLine("Custom signing PDF document");
            using (PDFDoc doc = new PDFDoc(doc_path))
            {

                // Make sure that there is YubiKey, and if more than one, decide which one to use.
                var yubiKeyToUse = ChooseYubiKey();
                if (yubiKeyToUse is null)
                {
                    System.Diagnostics.Debug.WriteLine("No YubiKey");
                    return;
                    // handle case where no YubiKey was found.
                }

                // You could create the YubiKey session later in the code, but the original sample code potentially needs the certificate to
                // calculate a PAdES attribute, and rather than creating two PivSessions I chose to create a single one, and perform the rest of the 
                // processing within its scope. Feel free to swap things around.
                IYubiKeyConnection connection = yubiKeyToUse.Connect(YubiKeyApplication.Piv);
                using (var piv = new PivSession(yubiKeyToUse))
                {
                    Page page1 = doc.GetPage(1);
                    DigitalSignatureField digsig_field = doc.CreateDigitalSignatureField(cert_field_name);
                    SignatureWidget widgetAnnot = SignatureWidget.Create(doc, new Rect(143, 287, 219, 306), digsig_field);
                    page1.AnnotPushBack(widgetAnnot);

                    // (OPTIONAL) Add an appearance to the signature field.
                    Image img = Image.Create(doc, appearance_image_path);
                    widgetAnnot.CreateSignatureAppearance(img);

                    // Create a digital signature dictionary inside the digital signature field, in preparation for signing.
                    digsig_field.CreateSigDictForCustomSigning("Adobe.PPKLite", DigitalSignatureField.SubFilterType.e_adbe_pkcs7_detached, 7500); // For security reasons, set the contents size to a value greater than but as close as possible to the size you expect your final signature to be, in bytes.
                                                                                                                                                  // ... or, if you want to apply a certification signature, use CreateSigDictForCustomCertification instead.

                    // (OPTIONAL) Set the signing time in the signature dictionary, if no secure embedded timestamping support is available from your signing provider.
                    Date current_date = new Date();
                    current_date.SetCurrentTime();
                    digsig_field.SetSigDictTimeOfSigning(current_date);

                    doc.Save(output_path, SDFDoc.SaveOptions.e_incremental);

                    // Digest the relevant bytes of the document in accordance with ByteRanges surrounding the signature.
                    byte[] pdf_digest = digsig_field.CalculateDigest(digest_algorithm_type);

                    // Get the certificate with public key.
                    var cert = piv.GetCertificate(0x9C);

                    // Marshal into the type needed by Apryse
                    var signer_cert = new pdftron.Crypto.X509Certificate(cert.Export(X509ContentType.Cert));
                    // Build the certificate chain.
                    X509Chain chain = new X509Chain();
                    chain.Build(cert);

                    pdftron.Crypto.X509Certificate[] chain_certs = { };
                    for (int i = 0; i < chain.ChainElements.Count; i++)
                    {
                        var c = chain.ChainElements[i].Certificate.Export(X509ContentType.Cert);
                        chain_certs.Append(new pdftron.Crypto.X509Certificate(c));
                    }

                    // You could add PAdES attributes if you want (see the original sample), for now, let's keep things simple
                    // The signedAttrs are certain attributes that become protected by their inclusion in the signature.
                    byte[] signedAttrs = DigitalSignatureField.GenerateCMSSignedAttributes(pdf_digest);


                    // Calculate the digest of the signedAttrs (i.e. not the PDF digest, this time).
                    byte[] signedAttrs_digest = DigestAlgorithm.CalculateDigest(digest_algorithm_type, signedAttrs);

                    //////////////////////////// custom digest signing starts ////////////////////////////
                    //// At this point, you can sign the digest.

                    // The data that is passed to Azure is just the signedAttrs digest, but YubiKey requires that it is formatted in a different way, making it 
                    // somewhat longer. The length of the rsa needs to match what YubiKey expects otherwise exceptions about data length will be thrown.

                    //Need to map from the digest type that Apryse uses to that used by YubiKey
                    int algorithm = (int)RsaFormat.Sha256;
                    int rsaLength = 2048;
                    switch (digest_algorithm_type)
                    {
                        case DigestAlgorithm.Type.e_sha256:
                            algorithm = (int)RsaFormat.Sha256;
                            rsaLength = 2048;
                            break;
                        case DigestAlgorithm.Type.e_sha512:
                            algorithm = (int)RsaFormat.Sha512;
                            rsaLength = 4096;
                            break;
                        case DigestAlgorithm.Type.e_sha384:
                            algorithm = (int)RsaFormat.Sha384;
                            rsaLength = 3072;
                            break;
                        default:
                            throw new NotImplementedException();
                    }

                    var rsa = Yubico.YubiKey.Cryptography.RsaFormat.FormatPkcs1Sign(signedAttrs_digest, algorithm, rsaLength);
                    // Don't use Yubico.YubiKey.Cryptography.RsaFormat.FormatPkcs1Pss, as that will give a byte[] that looks correct, and can be "signed"
                    // but it won't match what is expected so the signature will be considered invalid.
      
                    // Everything is in place now for signing - You would probably want to ask the user to enter the PIN number or to press the YubiKey.
                    // In this example I have hard coded values into the KeyCollector class.

                    piv.KeyCollector = CallerSuppliedKeyCollector;

                    bool okPin = piv.TryVerifyPin();
                    //bool okKey = piv.TryAuthenticateManagementKey();

                    // if either of these values is not OK then signing will fail, so you should handle that.

                    byte[] signature_value = piv.Sign(0x9c, rsa);

                    //////////////////////////// custom digest signing ends //////////////////////////////

                    // Then, create ObjectIdentifiers for the algorithms you have used.
                    // Here we use digest_algorithm_type (usually SHA256) for hashing, and RSAES-PKCS1-v1_5 (specified in the private key) for signing.
                    ObjectIdentifier digest_algorithm_oid = new ObjectIdentifier(digest_algorithm_type);
                    ObjectIdentifier signature_algorithm_oid = new ObjectIdentifier(ObjectIdentifier.Predefined.e_RSA_encryption_PKCS1);

                    // Then, put the CMS signature components together.
                    byte[] cms_signature = DigitalSignatureField.GenerateCMSSignature(
                    signer_cert, chain_certs, digest_algorithm_oid, signature_algorithm_oid,
                    signature_value, signedAttrs);

                    // Write the signature to the document.
                    doc.SaveCustomSignature(cms_signature, digsig_field, output_path);
                }
            }
            Console.Out.WriteLine("================================================================================");
        }

        // I'm hard coding values - you probably shouldn't
        private static bool CallerSuppliedKeyCollector(KeyEntryData data)
        {
            if (data.Request == Yubico.YubiKey.KeyEntryRequest.AuthenticatePivManagementKey)
            {
                byte[] mk = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
                ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(mk);

                data.SubmitValue(span);
                return true;
            }
            if (data.Request == Yubico.YubiKey.KeyEntryRequest.Release)
            {
                data.Clear();
                return true;
            }
            if (data.Request == Yubico.YubiKey.KeyEntryRequest.VerifyPivPin)
            {
                var pn = "654321";
                var pin = GetReadOnlySpanFromString(pn);
                data.SubmitValue(pin);
                return true;
            }
            throw new NotImplementedException();
        }

        static ReadOnlySpan<byte> GetReadOnlySpanFromString(string value)
        {
            // Encode the string into bytes using UTF8 encoding
            byte[] byteArray = Encoding.UTF8.GetBytes(value);

            // Create a ReadOnlySpan<byte> from the byte array
            return new ReadOnlySpan<byte>(byteArray);
        }

        static IYubiKeyDevice? ChooseYubiKey()
        {
            IEnumerable<IYubiKeyDevice> list = YubiKeyDevice.FindAll();
            return list.First();
        }


        private static pdftron.PDFNetLoader pdfNetLoader = pdftron.PDFNetLoader.Instance();
        static Class1() { }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            // Initialize PDFNetC
            PDFNet.Initialize(PDFTronLicense.Key);

            bool result = true;

            System.Diagnostics.Debug.WriteLine(Directory.GetCurrentDirectory());


            //////////////////// TEST 6: Custom signing API.
            // The Apryse custom signing API is a set of APIs related to cryptographic digital signatures
            // which allows users to customize the process of signing documents. Among other things, this
            // includes the capability to allow for easy integration of PDF-specific signing-related operations
            // with access to Hardware Security Module (HSM) tokens/devices, access to cloud keystores, access
            // to system keystores, etc.

            try
            {
                CustomSigningAPIYubikey(@"C:\Users\RogerDunham\Downloads\PDFNetC64 (1)\PDFNetC64\Samples\TestFiles\waiver.pdf",
                    "PDFTronApprovalSig",
                    input_path + "signature.jpg",
                    DigestAlgorithm.Type.e_sha256,
                    output_path + "signed256a.pdf");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                result = false;
            }

            //////////////////// End of tests. ////////////////////
            PDFNet.Terminate();
            if (result)
            {
                Console.Out.WriteLine("Tests successful.\n==========");
            }
            else
            {
                Console.Out.WriteLine("Tests FAILED!!!\n==========");
            }
        }
    }
}
