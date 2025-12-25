using com.etsoo.AliAmapApi.Dto;
using com.etsoo.AliAmapApi.RQ;
using com.etsoo.ApiModel.Dto.Maps;

namespace com.etsoo.AliAmapApi
{
    /// <summary>
    /// Amap API service interface
    /// 高德地图 API 服务接口
    /// </summary>
    public interface IAmapService
    {
        /// <summary>
        /// Async autocomplete
        /// 异步自动填充
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<AmapAutocompleteResponse?> AutoCompleteAsync(AutocompleteRQ rq, CancellationToken cancellationToken = default);

        /// <summary>
        /// Async search place
        /// 异步查询地点
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<IEnumerable<PlaceCommon>?> SearchCommonPlaceAsync(SearchPlaceRQ rq, CancellationToken cancellationToken = default);

        /// <summary>
        /// Async search common place
        /// 异步查询通用地点
        /// </summary>
        /// <param name="rq">Request data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Result</returns>
        Task<AmapPlaceResponse?> SearchPlaceAsync(SearchPlaceRQ rq, CancellationToken cancellationToken = default);
    }
}