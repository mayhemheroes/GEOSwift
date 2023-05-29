#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import GEOSwift


@_cdecl("LLVMFuzzerTestOneInput")
public func GEOFUzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)

    let choice = fdp.ConsumeIntegralInRange(from: 0, to: 2)

    do {
        switch (choice) {
        case 0:
            try Geometry(wkb: fdp.ConsumeRemainingData())
        case 1:
            try Geometry(wkt: fdp.ConsumeRemainingString())
        case 2:
            let decoder = JSONDecoder()
            try decoder.decode(GeoJSON.self, from: fdp.ConsumeRemainingData())
        default:
            fatalError("Invalid fuzz choice")
        }
    }
    catch is GEOSwiftError {
        return -1
    }
    catch is GEOSError {
        return -1
    }
    catch is DecodingError {
        return -1
    }
    catch let error {
        print(error.localizedDescription)
        print(type(of: error))
        exit(EXIT_FAILURE)
    }
    return 0;
}