using System.Text.Json.Serialization;

namespace com.etsoo.AliAmapApi
{
    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DictionaryKeyPolicy = JsonKnownNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true)]
    [JsonSerializable(typeof(Dto.AmapAutocompleteResponse))]
    [JsonSerializable(typeof(Dto.AmapPlaceResponse))]
    internal partial class AliAmapApiCallJsonSerializerContext : JsonSerializerContext
    {
    }
}
