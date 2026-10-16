import CompanionCore
import SwiftUI
import UIKit
import VisionKit

/// Scan the QR code `codemode-mcp companion invite` shows on the gateway Mac
struct PairView: View {
    @Environment(AppManager.self) private var manager
    @State private var lastScanned: String?

    var body: some View {
        VStack(spacing: 16) {
            switch manager.state.pairing {
            case .registering, .checking:
                Spacer()
                ProgressView("Pairing with the gateway…")
                Spacer()
            default:
                Text("On the gateway Mac, run `codemode-mcp companion invite`, then scan the QR code it shows.")
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                if case let .failed(message) = manager.state.pairing {
                    Text(message)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    // a code that failed only because the gateway was out of
                    // reach still works once it is back; the scanner has
                    // stopped on that code, so it is retried from here
                    if let lastScanned {
                        Button("Try this code again") {
                            manager.dispatch(.pair(scanned: lastScanned))
                        }
                    }
                }
                scanner
                Button("Paste invite") {
                    if let text = UIPasteboard.general.string {
                        lastScanned = text
                        manager.dispatch(.pair(scanned: text))
                    }
                }
            }
        }
        .padding(.vertical)
        .navigationTitle("Pair")
    }

    @ViewBuilder
    private var scanner: some View {
        if DataScannerViewController.isSupported, DataScannerViewController.isAvailable {
            QRScanner { scanned in
                // the scanner restarts after a failed pairing with the code
                // still in view; it is tried again only when the owner asks
                guard scanned != lastScanned else { return }
                lastScanned = scanned
                manager.dispatch(.pair(scanned: scanned))
            }
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .padding(.horizontal)
        } else {
            ContentUnavailableView(
                "No camera",
                systemImage: "camera",
                description: Text("Copy the invite on another device and paste it here.")
            )
        }
    }
}

/// VisionKit's scanner, reporting the first QR code it reads
struct QRScanner: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()

        return scanner
    }

    func updateUIViewController(_: DataScannerViewController, context _: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        private var scanned = false

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func dataScanner(
            _ scanner: DataScannerViewController,
            didAdd items: [RecognizedItem],
            allItems _: [RecognizedItem]
        ) {
            for item in items {
                guard !scanned, case let .barcode(code) = item, let text = code.payloadStringValue else {
                    continue
                }
                scanned = true
                scanner.stopScanning()
                onScan(text)
            }
        }
    }
}
