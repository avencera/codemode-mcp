import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The share sheet's "CMCP Companion": keeps the file 1Password shares, such
/// as an item's `.p12`, for the app to attach to the read waiting for it
final class ShareViewController: UIViewController {
    private let model = ShareModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: ShareView(model: model) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        })
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)

        Task { await model.receive(extensionContext?.inputItems as? [NSExtensionItem] ?? []) }
    }
}

@MainActor
@Observable
final class ShareModel {
    enum Phase {
        case receiving
        case kept(name: String)
        case failed(String)
    }

    private(set) var phase = Phase.receiving

    func receive(_ items: [NSExtensionItem]) async {
        guard let provider = items.lazy.compactMap(\.attachments).joined().first(where: {
            $0.hasItemConformingToTypeIdentifier(UTType.data.identifier)
        }) else {
            phase = .failed("Nothing to keep: share one file from 1Password.")
            return
        }

        // the app may not open again soon, so files no read took go here too
        SharedInbox.purgeExpired()
        do {
            let (data, name) = try await Self.load(provider)
            try SharedInbox.store(data, name: name)
            phase = .kept(name: name)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    /// The file's bytes and name; read inside the callback, since the file
    /// the provider hands over is deleted when it returns
    private nonisolated static func load(_ provider: NSItemProvider) async throws -> (Data, String) {
        let suggestedName = provider.suggestedName
        return try await withCheckedThrowingContinuation { continuation in
            _ = provider.loadFileRepresentation(forTypeIdentifier: UTType.data.identifier) { url, error in
                guard let url else {
                    continuation.resume(throwing: error ?? CocoaError(.fileReadUnknown))
                    return
                }
                do {
                    let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                    guard size <= SharedInbox.maxBytes else {
                        throw SharedInbox.StoreError.tooLarge(size)
                    }
                    let data = try Data(contentsOf: url)
                    let name = suggestedName.map { suggested in
                        // a suggested name may lack the extension the file has
                        suggested.contains(".") || url.pathExtension.isEmpty
                            ? suggested : "\(suggested).\(url.pathExtension)"
                    } ?? url.lastPathComponent
                    continuation.resume(returning: (data, name))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

struct ShareView: View {
    let model: ShareModel
    let done: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Spacer()
                switch model.phase {
                case .receiving:
                    ProgressView()
                case let .kept(name):
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(.green)
                    Text("Kept \(name)")
                        .font(.headline)
                        .multilineTextAlignment(.center)
                    Text("Go back to the CMCP Companion app to send it. It is deleted if no read takes it within 5 minutes.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                case let .failed(message):
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(.red)
                    Text(message)
                        .multilineTextAlignment(.center)
                }
                Spacer()
            }
            .padding(24)
            .navigationTitle("CMCP Companion")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: done)
                }
            }
        }
    }
}
