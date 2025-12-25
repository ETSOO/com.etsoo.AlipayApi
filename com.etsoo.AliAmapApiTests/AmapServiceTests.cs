using com.etsoo.AliAmapApi;
using com.etsoo.AliAmapApi.RQ;
using com.etsoo.ApiModel.Dto.Maps;
using System.Text.Json;

namespace com.etsoo.AliAmapApiTests
{
    [TestClass]
    public class AmapServiceTests
    {
        readonly AmapService service;

        public AmapServiceTests()
        {
            var options = JsonSerializer.Deserialize<AmapOptions>(File.ReadAllText("C:\\api\\Amap.json")) ?? throw new Exception("No Amap Options");
            service = new AmapService(options, new HttpClient());
        }

        [TestMethod]
        public async Task AutocompleteAsyncTest()
        {
            var response = await service.AutoCompleteAsync(new AutocompleteRQ
            {
                Keywords = "玫瑰庭院"
            }, TestContext.CancellationToken);

            Assert.IsNotNull(response);

            var first = response.Tips?.First();
            Assert.IsNotNull(first);

            Assert.IsTrue(response.Tips?.Any(result => result.District.Contains("青岛市")));
        }

        [TestMethod]
        public async Task SearchPlaceAsyncTest()
        {
            var response = await service.SearchPlaceAsync(new SearchPlaceRQ
            {
                Keywords = "清溪路88号玫瑰庭院11号楼",
                PageSize = 3
            }, TestContext.CancellationToken);

            Assert.IsNotNull(response);

            Assert.AreEqual(3, response.Pois?.Count());

            var first = response.Pois?.First();
            Assert.IsNotNull(first);

            Assert.IsTrue(response.Pois?.Any(result => result.Cityname == "青岛市"));
        }

        [TestMethod]
        public async Task SearchCommonAsyncExample1Test()
        {
            var results = await service.SearchCommonPlaceAsync(new SearchPlaceRQ
            {
                Keywords = "广东省佛山市季华西路中国陶瓷总部基地中区E座"
            }, TestContext.CancellationToken);

            Assert.IsNotNull(results);

            var first = results.Where(a => a.City == "佛山市" && a.FormattedAddress.Contains("基地中区")).First();

            Assert.IsNotNull(first);
            Assert.AreEqual("CN", first.Region);
            Assert.AreEqual("广东省", first.State);
            Assert.AreEqual("禅城区", first.District);
            Assert.AreEqual("广东省佛山市禅城区季华西路中国陶瓷产业总部基地中区E座", first.FormattedAddress);
        }

        [TestMethod]
        public async Task QueryAroundTest()
        {
            var location = new Location(39.915F, 116.404F);
            var results = await service.SearchCommonPlaceAsync(new SearchPlaceRQ
            {
                Keywords = "民生银行+",
                Location = location,
                Radius = 1000,
                PageSize = 3
            }, TestContext.CancellationToken);

            Assert.IsNotNull(results);

            var item = results.FirstOrDefault(result => result.Name.StartsWith("中国民生银行"));
            Assert.IsNotNull(item);

            Assert.AreEqual((int)location.Lat, (int)item.Location.Lat);
            Assert.AreEqual((int)location.Lng, (int)item.Location.Lng);
        }

        public required TestContext TestContext { get; set; }
    }
}
