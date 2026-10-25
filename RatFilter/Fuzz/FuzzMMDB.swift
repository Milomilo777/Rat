import Foundation

@_cdecl("LLVMFuzzerTestOneInput")
public func FuzzMMDB(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int {
    if size == 0 { return 0 }
    let buffer = UnsafeBufferPointer(start: data, count: size)
    let d = Data(buffer: buffer)
    if let db = try? MMDB(data: d) {
        _ = db.lookup("8.8.8.8")
    }
    return 0
}
