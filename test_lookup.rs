fn main() {
    let r: Result<maxminddb::geoip2::City, _> = maxminddb::Reader::open_readfile("").unwrap().lookup("1.1.1.1".parse().unwrap());
}
