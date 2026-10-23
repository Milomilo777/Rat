import Foundation

@_cdecl("LLVMFuzzerTestOneInput")
public func FuzzRule(_ data: UnsafePointer<UInt8>, _ size: Int) -> Int {
    if size == 0 { return 0 }
    let buffer = UnsafeBufferPointer(start: data, count: size)
    let d = Data(buffer: buffer)
    _ = try? RuleExport.decode(d)
    return 0
}
