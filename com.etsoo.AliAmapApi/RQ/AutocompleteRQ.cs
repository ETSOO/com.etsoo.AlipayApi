namespace com.etsoo.AliAmapApi.RQ
{
    /// <summary>
    /// Autocomplete request data
    /// https://lbs.amap.com/api/webservice/guide/api-advanced/inputtips
    /// </summary>
    public record AutocompleteRQ : AmapBaseRQ
    {
        /// <summary>
        /// Place types
        /// 指定地点类型
        /// </summary>
        public IEnumerable<string>? Type { get; init; }

        /// <summary>
        /// City
        /// 城市
        /// </summary>
        public string? City { get; init;  }
    }
}
