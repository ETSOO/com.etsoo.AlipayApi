using com.etsoo.Utils;
using com.etsoo.Utils.String;
using System.Security.Cryptography;

namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Amap base request
    /// 高德地图基础请求
    /// </summary>
    internal record AmapRequestBase
    {
        private readonly string? _privateKey;

        /// <summary>
        /// Parameters
        /// 参数
        /// </summary>
        protected readonly SortedDictionary<string, string> Parameters = [];

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="rq">Base request data</param>
        /// <param name="key">API Key</param>
        /// <param name="privateKey">Private key</param>
        protected AmapRequestBase(AmapBaseRQ rq, string key, string? privateKey)
        {
            _privateKey = privateKey;

            AddOutput(rq);

            Parameters["key"] = key;
            Parameters["keywords"] = rq.Keywords;

            if (rq.Location != null)
            {
                Parameters["location"] = rq.Location.ToLngLatString();
            }

            if (rq.CityLimit.HasValue)
            {
                Parameters["citylimit"] = rq.CityLimit.Value.ToString();
            }
        }

        /// <summary>
        /// Add output parameter
        /// 添加输出参数
        /// </summary>
        /// <param name="rq">Request data</param>
        protected virtual void AddOutput(AmapBaseRQ rq)
        {
            Parameters["output"] = rq.Output.ToString().ToUpper();
        }

        /// <summary>
        /// To query string
        /// 输出查询字符串
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public virtual async ValueTask<string> ToQueryAsync(CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrEmpty(_privateKey))
            {
                // 在计算md5的参数如果出现＋号，请正常计算sig，但在请求的时候，需要用urlencode进行编码再请求
                var query = Parameters.JoinAsString().TrimEnd('&');

                var signBytes = await MD5.HashDataAsync(SharedUtils.GetStream(query + _privateKey), cancellationToken);
                var sign = Convert.ToHexString(signBytes).ToLower();

                Parameters["sig"] = sign;
            }

            return Parameters.JoinAsQuery().TrimEnd('&');
        }
    }
}
