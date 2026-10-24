fn main() {
    println!("{:?}", idna::domain_to_ascii("www.测试.com"));
    println!("{:?}", idna::domain_to_unicode("www.xn--0zwm56d.com"));
}
