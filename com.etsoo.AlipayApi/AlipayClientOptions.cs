using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;

namespace com.etsoo.AlipayApi
{
    /// <summary>
    /// Alipay client options
    /// 支付宝客户端选项
    /// </summary>
    public record AlipayClientOptions
    {
        /// <summary>
        /// 程序编号
        /// </summary>
        [Required]
        public required string AppId { get; set; }

        /// <summary>
        /// 网关地址，默认为 https://openapi.alipay.com/gateway.do
        /// </summary>
        [Url]
        public string? Gateway { get; set; }

        /// <summary>
        /// 开发设置 - 授权回调地址，用于服务器端应用
        /// </summary>
        [Url]
        public string? ServerRedirectUrl { get; set; }

        /// <summary>
        /// 开发设置 - 授权回调地址，用于网页端应用
        /// </summary>
        [Url]
        public string? ScriptRedirectUrl { get; set; }

        /// <summary>
        /// 接口证书加签私匙，应用私钥RSA2048-敏感数据，请妥善保管.txt
        /// </summary>
        public string? RsaPrivateKey { get; set; }

        /// <summary>
        /// 接口证书加签公匙，应用公钥RSA2048.txt
        /// </summary>
        public string? RsaPublicKey { get; set; }

        /// <summary>
        /// 程序公钥SN，内部通过安全程序打开 appCertPublicKey_*.crt 计算可得
        /// </summary>
        public string? AppCertSN { get; set; }

        /// <summary>
        /// 支付宝公钥文件 alipayCertPublicKey_RSA2.crt 路径
        /// </summary>
        public string? AlipayPublicKeyFile { get; set; }

        /// <summary>
        /// 支付宝公钥SN，内部通过安全程序打开 alipayCertPublicKey_RSA2.crt 计算可得
        /// </summary>
        public string? AlipayCertSN { get; set; }

        /// <summary>
        /// 支付宝根证书SN，内部通过安全程序打开 alipayRootCert.crt 计算可得
        /// </summary>
        public string? AlipayRootCertSN { get; set; }
    }

    [OptionsValidator]
    public partial class ValidateAlipayClientOptions : IValidateOptions<AlipayClientOptions>
    {
    }
}
