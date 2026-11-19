// Print recognized text for each image: "<file>\t<line>" (macOS Vision, accurate mode).
// swiftc -O ocr.swift -o ocr && ./ocr frame*.png
import Foundation
import Vision
import AppKit

for path in CommandLine.arguments.dropFirst() {
    guard let img = NSImage(contentsOfFile: path),
          let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { continue }
    let req = VNRecognizeTextRequest()
    req.recognitionLevel = .accurate
    req.usesLanguageCorrection = false
    try? VNImageRequestHandler(cgImage: cg).perform([req])
    for obs in req.results ?? [] {
        if let s = obs.topCandidates(1).first?.string {
            print("\((path as NSString).lastPathComponent)\t\(s)")
        }
    }
}
