using com.etsoo.AlipayApi.Auth;
using com.etsoo.ApiModel.Auth;
using com.etsoo.HTTP;
using com.etsoo.Utils.Actions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Web;

namespace com.etsoo.AlipayApi
{
    /// <summary>
    /// Alipay client, based on Alipay open platform
    /// https://open.alipay.com/develop/manage
    /// 支付宝客户端，基于支付宝开放平台
    /// </summary>
    public class AlipayClient : HttpClientService, IAlipayClient
    {
        private const string SignScope = "auth_user";

        /// <summary>
        /// Default gateway
        /// 默认网关地址
        /// </summary>
        public const string DefaultGateway = "https://openapi.alipay.com/gateway.do";

        private readonly HttpClient _client;
        private readonly AlipayClientOptions _options;
        private readonly ILogger _logger;

        private readonly string _gateway;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="client">Client</param>
        /// <param name="options">Options</param>
        public AlipayClient(HttpClient client, AlipayClientOptions options, ILogger logger) : base(client)
        {
            _client = client;
            _options = options;
            _logger = logger;

            _gateway = options.Gateway ?? DefaultGateway;
        }

        public AlipayClient(HttpClient client, IOptions<AlipayClientOptions> options, ILogger<AlipayClient> logger)
            : this(client, options.Value, logger)
        {
        }

        /// <summary>
        /// Get sign in URL
        /// 获取登录URL
        /// </summary>
        /// <param name="state">Request state</param>
        /// <param name="loginHint">Login hint</param>
        /// <returns>URL</returns>
        public string GetSignInUrl(string state, string? loginHint = null)
        {
            return GetServerAuthUrl(AuthExtentions.SignInAction, state, SignScope, false, loginHint);
        }

        /// <summary>
        /// Get sign up URL
        /// 获取注册URL
        /// </summary>
        /// <param name="state">Request state</param>
        /// <returns>URL</returns>
        public string GetSignUpUrl(string state)
        {
            return GetServerAuthUrl(AuthExtentions.SignUpAction, state, SignScope);
        }

        /// <summary>
        /// Get API data
        /// 获取接口数据
        /// </summary>
        /// <param name="apiData">Additonal API data</param>
        /// <param name="withSignature">With or without signature</param>
        /// <returns>Result</returns>
        private SortedDictionary<string, string> GetApiData(Dictionary<string, string> apiData, bool withSignature = true)
        {
            // Default encoding is UTF-8 instead of GBK
            SortedDictionary<string, string> data = new()
            {
                ["charset"] = "UTF-8",
                ["format"] = "json",
                ["app_id"] = _options.AppId,
                ["version"] = "1.0",
                ["sign_type"] = "RSA2",
                ["timestamp"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            };

            if (_options.AlipayRootCertSN != null)
            {
                data["alipay_root_cert_sn"] = _options.AlipayRootCertSN;
            }

            if (_options.AppCertSN != null)
            {
                data["app_cert_sn"] = _options.AppCertSN;
            }

            foreach (var item in apiData)
            {
                data[item.Key] = item.Value;
            }

            if (withSignature)
            {
                data["sign"] = CreateSignData(data);
            }

            return data;
        }

        /// <summary>
        /// Sign data
        /// 信息签名
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <returns>Result</returns>
        private string CreateSignData(SortedDictionary<string, string> data)
        {
            var content = new StringBuilder();
            foreach (var (key, value) in data)
            {
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }
                content.Append(key).Append('=').Append(value).Append('&');
            }

            // Remove the last &
            var source = Encoding.UTF8.GetBytes(content.ToString().TrimEnd('&'));

            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(_options.RsaPrivateKey!), out var _);

            var sign = Convert.ToBase64String(rsa.SignData(source, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            return sign;
        }

        /// <summary>
        /// Get server auth URL, for back-end processing
        /// 获取服务器授权URL，用于后端处理
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="offline">Set to true if your application needs to refresh access tokens when the user is not present at the browser</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's OpenID</param>
        /// <returns>URL</returns>
        public string GetServerAuthUrl(string action, string state, string scope, bool offline = false, string? loginHint = null)
        {
            if (offline) scope += " offline_access";

            return GetAuthUrl($"{_options.ServerRedirectUrl}/{action}", "code", scope, state, loginHint);
        }

        /// <summary>
        /// Get script auth URL, for front-end page
        /// 获取脚本授权URL，用于前端页面
        /// </summary>
        /// <param name="action">Action of the request</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's OpenID</param>
        /// <returns>URL</returns>
        public string GetScriptAuthUrl(string action, string state, string scope, string? loginHint = null)
        {
            return GetAuthUrl($"{_options.ScriptRedirectUrl}/{action}", "token", scope, state, loginHint);
        }

        /// <summary>
        /// Get auth URL
        /// 获取授权URL
        /// </summary>
        /// <param name="redirectUrl">The value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client, which you configured in your client's API Console</param>
        /// <param name="responseType">Set the parameter value to 'code' for web server applications or 'token' for SPA</param>
        /// <param name="scope">A space-delimited list of scopes that identify the resources that your application could access on the user's behalf</param>
        /// <param name="state">Specifies any string value that your application uses to maintain state between your authorization request and the authorization server's response</param>
        /// <param name="loginHint">Set the parameter value to an email address or sub identifier, which is equivalent to the user's OpenID</param>
        /// <returns>URL</returns>
        /// <exception cref="ArgumentNullException">Parameter 'redirectUrl' is required</exception>
        public string GetAuthUrl(string? redirectUrl, string responseType, string scope, string state, string? loginHint = null)
        {
            if (string.IsNullOrEmpty(redirectUrl))
            {
                throw new ArgumentNullException(nameof(redirectUrl));
            }

            return $"https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id={_options.AppId}&scope={HttpUtility.UrlEncode(scope)}&state={HttpUtility.UrlEncode(state)}&redirect_uri={HttpUtility.UrlEncode(redirectUrl)}";
        }

        /// <summary>
        /// Get user info
        /// 获取用户信息
        /// </summary>
        /// <param name="tokenData">Token data</param>
        /// <returns>Result</returns>
        public async ValueTask<AlipayUserInfo?> GetUserInfoAsync(AlipayTokenData tokenData)
        {
            var data = GetApiData(new Dictionary<string, string>
            {
                ["method"] = "alipay.user.info.share",
                ["auth_token"] = tokenData.AccessToken
            });

            var response = await _client.PostAsync(_gateway, new FormUrlEncodedContent(data));

            return await VerifyResponseAsync(response, "alipay_user_info_share_response", AlipayJsonSerializerContext.Default.AlipayUserInfo);
        }

        /// <summary>
        /// Get user info from callback request
        /// 从回调请求获取用户信息
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="state">Request state</param>
        /// <param name="action">Request action</param>
        /// <returns>Action result & user information</returns>
        public ValueTask<(IActionResult result, AuthUserInfo? userInfo)> GetUserInfoAsync(HttpRequest request, string state, string? action = null)
        {
            return GetUserInfoAsync(request, s => s == state, action);
        }

        /// <summary>
        /// Get user info from callback request
        /// 从回调请求获取用户信息
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="stateCallback">Callback to verify request state</param>
        /// <param name="action">Request action</param>
        /// <returns>Action result & user information</returns>
        public async ValueTask<(IActionResult result, AuthUserInfo? userInfo)> GetUserInfoAsync(HttpRequest request, Func<string, bool> stateCallback, string? action = null)
        {
            var (result, tokenData) = await ValidateAuthAsync(request, stateCallback, action);
            AuthUserInfo? userInfo = null;
            if (result.Ok && tokenData != null)
            {
                var data = await GetUserInfoAsync(tokenData);
                if (data == null)
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "userinfo"
                    };
                }
                else
                {
                    userInfo = new AuthUserInfo
                    {
                        OpenId = data.OpenId,
                        Name = data.NickName ?? "Unknown",
                        Picture = data.Avatar
                    };
                }
            }

            return (result, userInfo);
        }

        /// <summary>
        /// Create access token from authorization code
        /// 从授权码创建访问令牌
        /// </summary>
        /// <param name="action">Request action</param>
        /// <param name="code">Authorization code</param>
        /// <returns>Token data</returns>
        public async ValueTask<AlipayTokenData?> CreateTokenAsync(string action, string code)
        {
            var data = GetApiData(new Dictionary<string, string>
            {
                ["method"] = "alipay.system.oauth.token",
                ["grant_type"] = "authorization_code",
                ["code"] = code
            });

            var response = await _client.PostAsync(_gateway, new FormUrlEncodedContent(data));

            return await VerifyResponseAsync(response, "alipay_system_oauth_token_response", AlipayJsonSerializerContext.Default.AlipayTokenData);
        }

        private async Task<T?> VerifyResponseAsync<T>(HttpResponseMessage response, string responseField, JsonTypeInfo<T> typeInfo)
        {
            response.EnsureSuccessStatusCode();

            var charset = response.Content.Headers.ContentType?.CharSet;
            Encoding encoding = Encoding.UTF8;
            Stream stream;
            if (!string.IsNullOrEmpty(charset) && charset != "UTF-8")
            {
                // Even encoding is set to UTF-8, the response may still be in GBK
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                encoding = Encoding.GetEncoding(charset);

                // Transcoding stream
                stream = Encoding.CreateTranscodingStream(await response.Content.ReadAsStreamAsync(), encoding, Encoding.UTF8);
            }
            else
            {
                stream = await response.Content.ReadAsStreamAsync();
            }

            return await VerifySignAsync(stream, encoding, responseField, typeInfo);
        }

        /// <summary>
        /// Refresh the access token with refresh token
        /// 用刷新令牌获取访问令牌
        /// </summary>
        /// <param name="refreshToken">Refresh token</param>
        /// <returns>Result</returns>
        public async Task<AlipayTokenData?> RefreshTokenAsync(string refreshToken)
        {
            var data = GetApiData(new Dictionary<string, string>
            {
                ["method"] = "alipay.system.oauth.token",
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            });

            var response = await _client.PostAsync(_gateway, new FormUrlEncodedContent(data));

            return await VerifyResponseAsync(response, "alipay_system_oauth_token_response", AlipayJsonSerializerContext.Default.AlipayTokenData);
        }

        private async Task<T?> VerifySignAsync<T>(Stream stream, Encoding encoding, string responseField, JsonTypeInfo<T> typeInfo, bool disposeStream = true)
        {
            using var doc = await JsonDocument.ParseAsync(stream);

            if (disposeStream)
                await stream.DisposeAsync();

            if (doc.RootElement.TryGetProperty(responseField, out var json))
            {
                if (!doc.RootElement.TryGetProperty("alipay_cert_sn", out var alipayCertCN) || alipayCertCN.GetString()?.Equals(_options.AlipayCertSN) is true)
                {
                    // Error
                    if (json.TryGetProperty("code", out var code) && code.GetString() != "10000")
                    {
                        throw new Exception(json.GetRawText());
                    }

                    var sign = doc.RootElement.GetProperty("sign").GetString();

                    var rsa = RSA.Create();
                    var cert = X509Certificate2.CreateFromCertFile(_options.AlipayPublicKeyFile!);
                    rsa.ImportRSAPublicKey(cert.GetPublicKey(), out _);

                    var rawData = json.GetRawText();

                    var verified = rsa.VerifyData(encoding.GetBytes(rawData), Convert.FromBase64String(sign!), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    if (verified)
                    {
                        return json.Deserialize(typeInfo);
                    }
                    else
                    {
                        throw new Exception("Sign data verification failed");
                    }
                }
                else
                {
                    throw new Exception("Alipay certificate SN not matched");
                }
            }
            else
            {
                throw new Exception($"Response field {responseField} not found");
            }
        }

        /// <summary>
        /// Validate auth callback
        /// 验证认证回调
        /// </summary>
        /// <param name="request">Callback request</param>
        /// <param name="stateCallback">Callback to verify request state</param>
        /// <param name="action">Request action</param>
        /// <returns>Action result & Token data</returns>
        public async Task<(IActionResult result, AlipayTokenData? tokenData)> ValidateAuthAsync(HttpRequest request, Func<string, bool> stateCallback, string? action = null)
        {
            IActionResult result;
            AlipayTokenData? tokenData = null;

            if (request.Query.TryGetValue("error", out var error))
            {
                result = new ActionResult
                {
                    Type = "AccessDenied",
                    Field = error
                };
            }
            else if (request.Query.TryGetValue("state", out var actualState) && request.Query.TryGetValue("auth_code", out var codeSource))
            {
                var code = codeSource.ToString();
                if (!stateCallback(actualState.ToString()))
                {
                    result = new ActionResult
                    {
                        Type = "AccessDenied",
                        Field = "state"
                    };
                }
                else if (string.IsNullOrEmpty(code))
                {
                    result = new ActionResult
                    {
                        Type = "NoDataReturned",
                        Field = "code"
                    };
                }
                else
                {
                    try
                    {
                        action ??= request.GetRequestAction();
                        tokenData = await CreateTokenAsync(action, code);

                        if (tokenData == null)
                        {
                            result = new ActionResult
                            {
                                Type = "NoDataReturned",
                                Field = "token"
                            };
                        }
                        else
                        {
                            result = ActionResult.Success;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Create token failed");
                        result = ActionResult.From(ex);
                    }
                }
            }
            else
            {
                result = new ActionResult
                {
                    Type = "NoDataReturned",
                    Field = "state"
                };
            }

            return (result, tokenData);
        }
    }
}
