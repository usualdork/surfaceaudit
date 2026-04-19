"""Unit tests for the AssetClassifier."""

from surfaceaudit.classifier import AssetClassifier
from surfaceaudit.models import AssetType, GeoLocation, RawAsset, Service


def _make_raw(
    ip: str = "1.2.3.4",
    hostname: str | None = None,
    ports: list[int] | None = None,
    data: list[dict] | None = None,
) -> RawAsset:
    return RawAsset(
        ip=ip,
        hostname=hostname,
        ports=ports or [],
        data=data or [],
    )


class TestDetermineType:
    """Tests for _determine_type classification logic."""

    def test_web_server_by_port(self):
        classifier = AssetClassifier()
        for port in (80, 443, 8080, 8443):
            raw = _make_raw(ports=[port])
            assert classifier._determine_type(raw) == AssetType.WEB_SERVER

    def test_web_server_by_banner(self):
        classifier = AssetClassifier()
        for keyword in ("HTTP/1.1 200 OK", "nginx", "Apache"):
            raw = _make_raw(data=[{"data": keyword}])
            assert classifier._determine_type(raw) == AssetType.WEB_SERVER

    def test_database_by_port(self):
        classifier = AssetClassifier()
        for port in (3306, 5432, 27017, 6379, 1433):
            raw = _make_raw(ports=[port])
            assert classifier._determine_type(raw) == AssetType.DATABASE

    def test_database_by_banner(self):
        classifier = AssetClassifier()
        for keyword in ("MySQL", "PostgreSQL", "MongoDB", "Redis"):
            raw = _make_raw(data=[{"data": keyword}])
            assert classifier._determine_type(raw) == AssetType.DATABASE

    def test_iot_device_by_port(self):
        classifier = AssetClassifier()
        for port in (1883, 8883):
            raw = _make_raw(ports=[port])
            assert classifier._determine_type(raw) == AssetType.IOT_DEVICE

    def test_iot_device_by_banner(self):
        classifier = AssetClassifier()
        for keyword in ("MQTT", "CoAP", "Zigbee"):
            raw = _make_raw(data=[{"data": keyword}])
            assert classifier._determine_type(raw) == AssetType.IOT_DEVICE

    def test_network_device_by_port(self):
        classifier = AssetClassifier()
        for port in (161, 162):
            raw = _make_raw(ports=[port])
            assert classifier._determine_type(raw) == AssetType.NETWORK_DEVICE

    def test_network_device_by_banner(self):
        classifier = AssetClassifier()
        for keyword in ("SNMP", "Cisco", "MikroTik"):
            raw = _make_raw(data=[{"data": keyword}])
            assert classifier._determine_type(raw) == AssetType.NETWORK_DEVICE

    def test_other_fallback(self):
        classifier = AssetClassifier()
        raw = _make_raw(ports=[9999])
        assert classifier._determine_type(raw) == AssetType.OTHER

    def test_empty_asset_is_other(self):
        classifier = AssetClassifier()
        raw = _make_raw()
        assert classifier._determine_type(raw) == AssetType.OTHER


class TestExtractOs:
    def test_os_from_first_match(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"os": "Linux"}, {"os": "Windows"}])
        assert classifier._extract_os(raw) == "Linux"

    def test_os_skips_none(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"os": None}, {"os": "FreeBSD"}])
        assert classifier._extract_os(raw) == "FreeBSD"

    def test_os_skips_empty_string(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"os": ""}, {"os": "Ubuntu"}])
        assert classifier._extract_os(raw) == "Ubuntu"

    def test_os_none_when_absent(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"port": 80}])
        assert classifier._extract_os(raw) is None

    def test_os_none_when_no_data(self):
        classifier = AssetClassifier()
        raw = _make_raw()
        assert classifier._extract_os(raw) is None


class TestExtractServices:
    def test_extracts_service_fields(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{
            "port": 80,
            "transport": "tcp",
            "product": "nginx",
            "version": "1.18.0",
            "data": "HTTP/1.1 200 OK",
        }])
        services = classifier._extract_services(raw)
        assert len(services) == 1
        svc = services[0]
        assert svc.port == 80
        assert svc.protocol == "tcp"
        assert svc.name == "nginx"
        assert svc.version == "1.18.0"
        assert svc.banner == "HTTP/1.1 200 OK"

    def test_defaults_protocol_to_tcp(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"port": 443}])
        services = classifier._extract_services(raw)
        assert services[0].protocol == "tcp"

    def test_skips_entries_without_port(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"data": "banner"}, {"port": 22}])
        services = classifier._extract_services(raw)
        assert len(services) == 1
        assert services[0].port == 22

    def test_multiple_services(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[
            {"port": 80, "product": "nginx"},
            {"port": 443, "product": "nginx"},
        ])
        services = classifier._extract_services(raw)
        assert len(services) == 2

    def test_empty_data(self):
        classifier = AssetClassifier()
        raw = _make_raw()
        assert classifier._extract_services(raw) == []


class TestExtractGeolocation:
    def test_extracts_full_location(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{
            "location": {
                "country_name": "United States",
                "city": "San Francisco",
                "latitude": 37.7749,
                "longitude": -122.4194,
            }
        }])
        geo = classifier._extract_geolocation(raw)
        assert geo is not None
        assert geo.country == "United States"
        assert geo.city == "San Francisco"
        assert geo.latitude == 37.7749
        assert geo.longitude == -122.4194

    def test_partial_location(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{
            "location": {"country_name": "Germany"}
        }])
        geo = classifier._extract_geolocation(raw)
        assert geo is not None
        assert geo.country == "Germany"
        assert geo.city is None

    def test_none_when_no_data(self):
        classifier = AssetClassifier()
        raw = _make_raw()
        assert classifier._extract_geolocation(raw) is None

    def test_none_when_no_location_key(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"port": 80}])
        assert classifier._extract_geolocation(raw) is None

    def test_none_when_location_is_empty(self):
        classifier = AssetClassifier()
        raw = _make_raw(data=[{"location": {}}])
        assert classifier._extract_geolocation(raw) is None


class TestClassify:
    def test_full_classification(self):
        classifier = AssetClassifier()
        raw = _make_raw(
            ip="10.0.0.1",
            hostname="web.example.com",
            ports=[80, 443],
            data=[{
                "port": 80,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.18.0",
                "data": "HTTP/1.1 200 OK",
                "os": "Linux",
                "location": {
                    "country_name": "US",
                    "city": "NYC",
                    "latitude": 40.7,
                    "longitude": -74.0,
                },
            }],
        )
        result = classifier.classify(raw)
        assert result.ip == "10.0.0.1"
        assert result.hostname == "web.example.com"
        assert result.asset_type == AssetType.WEB_SERVER
        assert result.os == "Linux"
        assert len(result.services) == 1
        assert result.geolocation is not None
        assert result.ports == [80, 443]
        assert result.raw_data == {"matches": raw.data}

    def test_empty_raw_asset(self):
        classifier = AssetClassifier()
        raw = _make_raw(ip="0.0.0.0")
        result = classifier.classify(raw)
        assert result.ip == "0.0.0.0"
        assert result.asset_type == AssetType.OTHER
        assert result.os is None
        assert result.services == []
        assert result.geolocation is None
        assert result.raw_data == {}
