using com.etsoo.AliAmapApi.Dto;
using com.etsoo.AliAmapApi.RQ;
using com.etsoo.ApiModel.Dto.Maps;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net.Http.Json;

namespace com.etsoo.AliAmapApi
{
    /// <summary>
    /// Amap API service
    /// 高德地图 API 服务
    /// </summary>
    public class AmapService : IAmapService
    {
        private readonly AmapOptions options;
        private readonly HttpClient client;

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="httpClient">HTTP client</param>
        public AmapService(AmapOptions options, HttpClient client)
        {
            client.BaseAddress = new Uri(options.BaseAddress);

            this.options = options;
            this.client = client;
        }

        /// <summary>
        /// Constructor
        /// 构造函数
        /// </summary>
        /// <param name="options">Options</param>
        /// <param name="httpClient">HTTP client</param>
        [ActivatorUtilitiesConstructor]
        public AmapService(IOptions<AmapOptions> options, HttpClient httpClient)
            : this(options.Value, httpClient)
        {
        }

        /// <summary>
        /// Async autocomplete
        /// 异步自动填充
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<AmapAutocompleteResponse?> AutoCompleteAsync(AutocompleteRQ rq, CancellationToken cancellationToken = default)
        {
            var request = new AmapAutocompleteRequest(rq, options.ApiKey, options.PrivateKey);

            var query = await request.ToQueryAsync(cancellationToken);

            var api = $"v3/assistant/inputtips?{query}";

            return await client.GetFromJsonAsync(api, AliAmapApiCallJsonSerializerContext.Default.AmapAutocompleteResponse, cancellationToken);
        }

        /// <summary>
        /// Async search place
        /// 异步查询地点
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<AmapPlaceResponse?> SearchPlaceAsync(SearchPlaceRQ rq, CancellationToken cancellationToken = default)
        {
            var request = new AmapRequest(rq, options.ApiKey, options.PrivateKey);

            var method = rq.Polygon?.Any() is true ? "polygon" : (rq.Location != null && rq.Radius != null ? "around" : "text");

            var query = await request.ToQueryAsync(cancellationToken);

            var api = $"v5/place/{method}?{query}";

            return await client.GetFromJsonAsync(api, AliAmapApiCallJsonSerializerContext.Default.AmapPlaceResponse, cancellationToken);
        }

        /// <summary>
        /// Async search common place
        /// 异步查询通用地点
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        public async Task<IEnumerable<PlaceCommon>?> SearchCommonPlaceAsync(SearchPlaceRQ rq, CancellationToken cancellationToken = default)
        {
            var response = await SearchPlaceAsync(rq, cancellationToken);
            return response?.Pois?.Select(p => p.CreateCommon(rq.Keywords));
        }
    }
}
