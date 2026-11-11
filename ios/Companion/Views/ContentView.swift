import CompanionCore
import SwiftUI

/// Pairing until a gateway is paired; then the takeover while one is open,
/// else the read or handoff waiting on the owner, else the gateway
struct ContentView: View {
    @Environment(AppManager.self) private var manager

    var body: some View {
        NavigationStack {
            if manager.state.gateway == nil {
                PairView()
            } else {
                switch manager.shown {
                case let .takeover(takeover):
                    // a view of its own per takeover, so a zoom or keyboard
                    // from one never carries to the next
                    TakeoverView(takeover: takeover)
                        .id("\(takeover.session) \(takeover.handoff ?? "")")
                case let .read(read):
                    // a view of its own per read, so nothing entered or
                    // attached for one is ever sent for the next
                    RequestView(read: read)
                        .id(read.id)
                case let .handoff(handoff):
                    HandoffView(handoff: handoff)
                        .id(handoff.id)
                case .gateway:
                    GatewayView()
                }
            }
        }
    }
}
