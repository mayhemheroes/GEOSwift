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

    let choice = fdp.ConsumeIntegralInRange(from: 0, to: 3)

    do {
        switch (choice) {
        case 0:
            try Geometry(wkb: fdp.ConsumeRemainingData())
        case 1:
            try Geometry(wkt: fdp.ConsumeRemainingString())
        case 2:
            let decoder = JSONDecoder()
            try decoder.decode(GeoJSON.self, from: fdp.ConsumeRemainingData())
        case 3:
            let first_geo = try Geometry(wkt: fdp.ConsumeRandomLengthString())
            let second_geo = try? Geometry(wkt: fdp.ConsumeRandomLengthString())

            let operation = fdp.ConsumeIntegralInRange(from: 0, to: 7)
            switch (operation) {
            case 0:
                try first_geo.buffer(by: fdp.ConsumeDouble())
            case 1:
                try first_geo.convexHull()
            case 2:
                try first_geo.intersection(with: second_geo ?? first_geo)
            case 3:
                try first_geo.minimumBoundingCircle()
            case 4:
                try first_geo.envelope()
            case 5:
                try first_geo.union(with: second_geo ?? first_geo)
            case 6:
                if let sg = second_geo {
                    try first_geo.difference(with: second_geo ?? first_geo)
                }
            case 7:
                try first_geo.polygonize()
            case 8:
                try first_geo.contains(second_geo ?? first_geo)
            case 9:
                try first_geo.isDisjoint(with: second_geo ?? first_geo)
            case 10:
                try first_geo.touches(second_geo ?? first_geo)
            case 11:
                try first_geo.crosses(second_geo ?? first_geo)
            case 12:
                try first_geo.overlaps(second_geo ?? first_geo)
            case 13:
                try first_geo.relate(second_geo ?? first_geo)
            default:
                fatalError("Invalid fuzz choice")
            }


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