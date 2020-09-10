using System;
using RestSharp;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using Org.BouncyCastle.OpenSsl;
using System.Collections.Generic;
using System.Security.Claims;
using Newtonsoft.Json;

namespace Com.Zoominfo.Api
{
    public class AuthClient
    {
        private static readonly String BASE_URL = "https://api.zoominfo.com";
        private static readonly String ENTERPRISE_API_AUDIENCE = "enterprise_api";
        private static readonly String USERNAME_CLAIM = "username";
        private static readonly String CLIENT_ID_CLAIM = "client_id";
        private static readonly String IAT_CLAIM = "iat";
        private static readonly String EXP_CLAIM = "exp";
        private static readonly String ISSUER = "api-client@zoominfo.com";

        private string password;
        private string username;
        private string clientId;
        private string privateKey;

        private bool authWithUsernameAndPassword = false;

        public AuthClient(string username, string clientId, string privateKey)
        {
            authWithUsernameAndPassword = false;
            this.username = username;
            this.clientId = clientId;
            this.privateKey = privateKey;
        }

        public AuthClient(string username, string password)
        {
            authWithUsernameAndPassword = true;
            this.username = username;
            this.password = password;
        }

        public string getAccessToken()
        {
            System.Net.ServicePointManager.Expect100Continue = true;
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls
                   | System.Net.SecurityProtocolType.Tls11
                   | System.Net.SecurityProtocolType.Tls12;

            string message = "";
            try
            {
                if (authWithUsernameAndPassword)
                {
                    RestClient restClient = new RestClient(BASE_URL);
                    RestRequest restRequest = new RestRequest("/authenticate", Method.POST);
                    restRequest.AddJsonBody("{\"username\": " + username + ", \"password\": " + password + "}");
                    RestResponse restResponse = (RestResponse)restClient.Execute(restRequest);
                    dynamic json = JsonConvert.DeserializeObject(restResponse.Content.ToString());
                    return json.jwt.Value;
                }
                else
                {
                    string clientJwt = this.generateClientToken();
                    RestClient restClient = new RestClient(BASE_URL);
                    RestRequest restRequest = new RestRequest("/authenticate", Method.POST);
                    restRequest.AddHeader("Authorization", "Bearer " + clientJwt);
                    RestResponse restResponse = (RestResponse)restClient.Execute(restRequest);
                    dynamic json = JsonConvert.DeserializeObject(restResponse.Content.ToString());
                    return json.jwt.Value;
                }


            }
            catch (Exception exc)
            {
                message = exc.Message;
            }
            throw new Exception(string.Format("Auth Failed: {0}", message));
        }

        private string generateClientToken()
        {
            try
            {

                RSACryptoServiceProvider csp = getCSPFromPrivateKey(this.privateKey);
                RsaSecurityKey key = new RsaSecurityKey(csp);
                var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

                // claims
                DateTime now = DateTime.UtcNow;
                var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                var issueTime = now.AddMinutes(-2);
                var iat = (int)issueTime.Subtract(utc0).TotalSeconds;
                var expireTime = now.AddMinutes(3);
                var exp = (int)expireTime.Subtract(utc0).TotalSeconds;

                List<System.Security.Claims.Claim> claims = new List<System.Security.Claims.Claim>();
                claims.Add(new System.Security.Claims.Claim(CLIENT_ID_CLAIM, this.clientId));
                claims.Add(new System.Security.Claims.Claim(USERNAME_CLAIM, this.username));
                claims.Add(new System.Security.Claims.Claim(IAT_CLAIM, iat.ToString(), ClaimValueTypes.Integer64));
                claims.Add(new System.Security.Claims.Claim(EXP_CLAIM, exp.ToString(), ClaimValueTypes.Integer64));

                var token = new JwtSecurityToken(ISSUER,
                                                ENTERPRISE_API_AUDIENCE,
                                                claims,
                                                signingCredentials: credentials);

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                string serializedToken = handler.WriteToken(token);
                return serializedToken;
            }
            catch (Exception exc)
            {
                throw new Exception(string.Format("Auth Failed: {0}", exc));
            }
        }

        public static RSACryptoServiceProvider getCSPFromPrivateKey(String privateKeyString)
        {
            using (TextReader privateKeyTextReader = new StringReader(privateKeyString))
            {
                PemReader pr = new PemReader(privateKeyTextReader);
                AsymmetricKeyParameter akp = (AsymmetricKeyParameter)pr.ReadObject();
                pr.Reader.Close();

                RsaPrivateCrtKeyParameters privateKeyParams = ((RsaPrivateCrtKeyParameters)akp);
                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }

    }
}